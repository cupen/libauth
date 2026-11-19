package totp

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newTestCredential(userID string) Credential {
	return Credential{
		UserID:              userID,
		State:               StatePending,
		EncryptedSecret:     []byte("sealed-bytes"),
		Algorithm:           AlgorithmSHA1,
		Digits:              6,
		Period:              30,
		EnrollmentExpiresAt: time.Unix(1_700_000_000, 0).UTC(),
		LastUsedStep:        -1,
	}
}

func TestMemoryStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	cred := newTestCredential("alice")

	if _, err := s.Get(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on empty store: err = %v, want ErrNotFound", err)
	}
	if err := s.Create(ctx, cred); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Revision != 1 {
		t.Fatalf("revision after Create = %d, want 1", got.Revision)
	}
	if got.State != StatePending || got.Digits != 6 || got.Period != 30 || got.LastUsedStep != -1 {
		t.Fatalf("Get returned %+v", got)
	}
	if err := s.Create(ctx, cred); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate Create: err = %v, want ErrConflict", err)
	}
	if err := s.Create(ctx, Credential{UserID: "bob", Revision: 3}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Create with revision 3: err = %v, want ErrConflict", err)
	}

	updated := got.Clone()
	updated.State = StateActive
	updated.EnrollmentExpiresAt = time.Time{}
	updated.LastUsedStep = 42
	if err := s.Update(ctx, updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err = s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get after Update: %v", err)
	}
	if got.Revision != 2 || got.State != StateActive || got.LastUsedStep != 42 {
		t.Fatalf("after Update: %+v", got)
	}
	if !got.EnrollmentExpiresAt.IsZero() {
		t.Fatalf("EnrollmentExpiresAt was not cleared: %v", got.EnrollmentExpiresAt)
	}

	if err := s.Update(ctx, updated); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale Update: err = %v, want ErrConflict", err)
	}
	if err := s.Update(ctx, Credential{UserID: "ghost", Revision: 1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("Update missing row: err = %v, want ErrConflict", err)
	}

	if err := s.Delete(ctx, "alice", 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("Delete with stale revision: err = %v, want ErrConflict", err)
	}
	if err := s.Delete(ctx, "ghost", 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("Delete missing row: err = %v, want ErrConflict", err)
	}
	if err := s.Delete(ctx, "alice", 2); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: err = %v, want ErrNotFound", err)
	}
}

// TestMemoryStoreDefensiveCopies makes sure no caller can mutate stored
// bytes, and that a stored credential cannot be changed through a handle
// that was created before it.
func TestMemoryStoreDefensiveCopies(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	cred := newTestCredential("alice")

	if err := s.Create(ctx, cred); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Mutating the caller's slice must not reach the store.
	cred.EncryptedSecret[0] = 'X'

	got, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.EncryptedSecret, []byte("sealed-bytes")) {
		t.Fatalf("stored secret mutated through caller slice: %q", got.EncryptedSecret)
	}
	// Mutating the returned copy must not reach the store either.
	got.EncryptedSecret[0] = 'Y'
	again, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(again.EncryptedSecret, []byte("sealed-bytes")) {
		t.Fatalf("stored secret mutated through returned copy: %q", again.EncryptedSecret)
	}
}

func TestMemoryStoreContextCancellation(t *testing.T) {
	s := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Create(ctx, newTestCredential("alice")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Create: err = %v, want context.Canceled", err)
	}
	if _, err := s.Get(ctx, "alice"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get: err = %v, want context.Canceled", err)
	}
	if err := s.Update(ctx, newTestCredential("alice")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Update: err = %v, want context.Canceled", err)
	}
	if err := s.Delete(ctx, "alice", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Delete: err = %v, want context.Canceled", err)
	}
}

// TestMemoryStoreConcurrentUpdates exercises the optimistic lock under
// contention: exactly one writer per revision wins.
func TestMemoryStoreConcurrentUpdates(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if err := s.Create(ctx, newTestCredential("alice")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	cur, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	const writers = 8
	var wg sync.WaitGroup
	results := make([]error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			next := cur.Clone()
			next.LastUsedStep = int64(i)
			results[i] = s.Update(ctx, next)
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for _, err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrConflict):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d concurrent updates succeeded, want exactly 1", wins)
	}
	final, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.Revision != 2 {
		t.Fatalf("revision = %d, want 2", final.Revision)
	}
}

func TestCredentialCloneIsDeep(t *testing.T) {
	orig := Credential{UserID: "alice", EncryptedSecret: []byte{1, 2, 3}}
	clone := orig.Clone()
	clone.EncryptedSecret[0] = 9
	if orig.EncryptedSecret[0] != 1 {
		t.Fatal("Clone shares the secret slice")
	}
	var zero Credential
	if got := zero.Clone(); got.EncryptedSecret != nil {
		t.Fatalf("Clone of a nil secret = %v, want nil", got.EncryptedSecret)
	}
}
