package totp

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const testIssuer = "libauth"

var errStoreBoom = errors.New("store exploded")

// testClock is a mutable clock shared with the Authenticator.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(unix int64) *testClock {
	return &testClock{now: time.Unix(unix, 0).UTC()}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *testClock) Set(unix int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = time.Unix(unix, 0).UTC()
}

func newTestAuth(t *testing.T, store Store, opts ...Option) (*Authenticator, *testClock) {
	t.Helper()
	clock := newTestClock(1_700_000_000)
	all := append([]Option{WithIssuer(testIssuer), WithNow(clock.Now)}, opts...)
	a, err := New(store, testKey(t), all...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, clock
}

// decodeSecret turns an Enrollment's Base32 secret back into raw bytes.
func decodeSecret(t *testing.T, enrolled *Enrollment) []byte {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrolled.Secret)
	if err != nil {
		t.Fatalf("decode secret %q: %v", enrolled.Secret, err)
	}
	return raw
}

// codeFor computes the 6-digit code a user's authenticator app would show at
// the given Unix time.
func codeFor(t *testing.T, enrolled *Enrollment, unix int64) string {
	t.Helper()
	return codeAt(decodeSecret(t, enrolled), stepAt(unix, DefaultPeriod), DefaultDigits, sha1New)
}

// enrollAndActivate returns an active credential plus its secret.
func enrollAndActivate(t *testing.T, a *Authenticator, clock *testClock, userID string) *Enrollment {
	t.Helper()
	enrolled, err := a.Enroll(context.Background(), userID, "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := a.Activate(context.Background(), userID, codeFor(t, enrolled, clock.Now().Unix())); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return enrolled
}

func TestNewValidation(t *testing.T) {
	key := testKey(t)
	cases := []struct {
		name string
		key  []byte
		opts []Option
	}{
		{"no issuer", key, nil},
		{"blank issuer", key, []Option{WithIssuer("   ")}},
		{"issuer with colon", key, []Option{WithIssuer("a:b")}},
		{"short key", key[:16], []Option{WithIssuer(testIssuer)}},
		{"long key", append(key, 0), []Option{WithIssuer(testIssuer)}},
		{"bad period", key, []Option{WithIssuer(testIssuer), WithPeriod(60)}},
		{"bad digits", key, []Option{WithIssuer(testIssuer), WithDigits(8)}},
		{"bad algorithm", key, []Option{WithIssuer(testIssuer), WithAlgorithm("SHA256")}},
		{"negative skew", key, []Option{WithIssuer(testIssuer), WithSkew(-1)}},
		{"large skew", key, []Option{WithIssuer(testIssuer), WithSkew(2)}},
		{"zero ttl", key, []Option{WithIssuer(testIssuer), WithEnrollmentTTL(0)}},
		{"negative ttl", key, []Option{WithIssuer(testIssuer), WithEnrollmentTTL(-time.Second)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(NewMemoryStore(), tc.key, tc.opts...); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New: err = %v, want ErrInvalidConfig", err)
			}
		})
	}

	if _, err := New(nil, key, WithIssuer(testIssuer)); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store: err = %v, want ErrInvalidConfig", err)
	}
	// nil options, nil clock and nil rand are all ignored.
	if _, err := New(NewMemoryStore(), key, WithIssuer(testIssuer), nil, WithNow(nil), WithRand(nil)); err != nil {
		t.Fatalf("New with nil options: %v", err)
	}
}

func TestEnrollShape(t *testing.T) {
	a, _ := newTestAuth(t, NewMemoryStore())
	enrolled, err := a.Enroll(context.Background(), "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enrolled.State != StatePending {
		t.Errorf("State = %q, want pending", enrolled.State)
	}
	secret := decodeSecret(t, enrolled)
	if len(secret) != SecretSize {
		t.Errorf("secret length = %d, want %d", len(secret), SecretSize)
	}
	if strings.ContainsRune(enrolled.Secret, '=') {
		t.Errorf("secret %q is padded", enrolled.Secret)
	}
	if got, want := enrolled.ExpiresAt, newTestClock(1_700_000_000).Now().Add(DefaultEnrollmentTTL); !got.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", got, want)
	}
	wantURI := "otpauth://totp/" + testIssuer + ":alice%40example.com?" +
		"secret=" + enrolled.Secret + "&issuer=" + testIssuer + "&algorithm=SHA1&digits=6&period=30"
	if enrolled.URI != wantURI {
		t.Errorf("URI =\n  %s\nwant\n  %s", enrolled.URI, wantURI)
	}
}

func TestEnrollRejectsBadArguments(t *testing.T) {
	a, _ := newTestAuth(t, NewMemoryStore())
	ctx := context.Background()
	if _, err := a.Enroll(ctx, "", "alice"); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("empty user ID: err = %v", err)
	}
	if _, err := a.Enroll(ctx, "alice", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("empty account: err = %v", err)
	}
	if _, err := a.Enroll(ctx, "alice", "bad:account"); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("colon account: err = %v", err)
	}
}

func TestEnrollRotatesPendingSecret(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)

	first, err := a.Enroll(ctx, "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	before, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	clock.Advance(time.Minute)
	second, err := a.Enroll(ctx, "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("re-Enroll: %v", err)
	}
	if first.Secret == second.Secret {
		t.Fatal("re-enrolling reused the secret")
	}
	if !second.ExpiresAt.After(first.ExpiresAt) {
		t.Errorf("re-enrollment did not extend the deadline: %v vs %v", first.ExpiresAt, second.ExpiresAt)
	}
	after, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Revision != before.Revision+1 {
		t.Errorf("revision = %d, want %d", after.Revision, before.Revision+1)
	}
	// The old secret no longer activates anything.
	if err := a.Activate(ctx, "alice", codeFor(t, first, clock.Now().Unix())); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("Activate with the old secret: err = %v, want ErrInvalidCode", err)
	}
	// The new one does.
	if err := a.Activate(ctx, "alice", codeFor(t, second, clock.Now().Unix())); err != nil {
		t.Errorf("Activate with the new secret: %v", err)
	}
}

func TestEnrollWhileActive(t *testing.T) {
	ctx := context.Background()
	a, clock := newTestAuth(t, NewMemoryStore())
	enrollAndActivate(t, a, clock, "alice")

	if _, err := a.Enroll(ctx, "alice", "alice@example.com"); !errors.Is(err, ErrAlreadyEnabled) {
		t.Fatalf("Enroll while active: err = %v, want ErrAlreadyEnabled", err)
	}
}

func TestActivateFlow(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)

	if err := a.Activate(ctx, "alice", "123456"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Activate unknown user: err = %v, want ErrNotEnrolled", err)
	}

	enrolled, err := a.Enroll(ctx, "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	// Verify is unavailable until activation.
	if err := a.Verify(ctx, "alice", codeFor(t, enrolled, clock.Now().Unix())); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("Verify while pending: err = %v, want ErrNotEnabled", err)
	}

	code := codeFor(t, enrolled, clock.Now().Unix())
	if err := a.Activate(ctx, "alice", code); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	state, err := a.Status(ctx, "alice")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if state != StateActive {
		t.Fatalf("Status = %q, want active", state)
	}

	// The activation code is consumed.
	if err := a.Verify(ctx, "alice", code); !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("Verify with the activation code: err = %v, want ErrCodeUsed", err)
	}
	// Re-activating with the consumed code reports it as used...
	if err := a.Activate(ctx, "alice", code); !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("second Activate with the same code: err = %v, want ErrCodeUsed", err)
	}
	// ...while any other code reports that the credential is already on.
	if err := a.Activate(ctx, "alice", "000000"); !errors.Is(err, ErrAlreadyEnabled) {
		t.Fatalf("second Activate with a different code: err = %v, want ErrAlreadyEnabled", err)
	}

	stored, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.State != StateActive || !stored.EnrollmentExpiresAt.IsZero() {
		t.Fatalf("stored credential after Activate = %+v", stored)
	}
	if stored.LastUsedStep != stepAt(clock.Now().Unix(), DefaultPeriod) {
		t.Fatalf("LastUsedStep = %d, want the activation step", stored.LastUsedStep)
	}
}

func TestEnrollmentExpiry(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)

	enrolled, err := a.Enroll(ctx, "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	clock.Advance(DefaultEnrollmentTTL + time.Second)

	if err := a.Activate(ctx, "alice", codeFor(t, enrolled, clock.Now().Unix())); !errors.Is(err, ErrEnrollmentExpired) {
		t.Fatalf("Activate after TTL: err = %v, want ErrEnrollmentExpired", err)
	}
	// Expiry does not delete the row.
	state, err := a.Status(ctx, "alice")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if state != StatePending {
		t.Fatalf("Status = %q, want pending", state)
	}
	// Exactly at the deadline the enrollment is still usable.
	other := NewMemoryStore()
	a2, clock2 := newTestAuth(t, other)
	enrolled2, err := a2.Enroll(ctx, "alice", "alice@example.com")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	clock2.Set(enrolled2.ExpiresAt.Unix())
	if err := a2.Activate(ctx, "alice", codeFor(t, enrolled2, clock2.Now().Unix())); err != nil {
		t.Fatalf("Activate at the deadline: %v", err)
	}
}

func TestVerifyAcceptsSkew(t *testing.T) {
	ctx := context.Background()
	a, clock := newTestAuth(t, NewMemoryStore())
	enrolled := enrollAndActivate(t, a, clock, "alice")
	base := clock.Now().Unix()

	// Next step is fine once the previous one has been consumed.
	clock.Advance(30 * time.Second)
	if err := a.Verify(ctx, "alice", codeFor(t, enrolled, base+30)); err != nil {
		t.Fatalf("Verify at +1 step: %v", err)
	}
	// A code from the previous step is accepted (still inside skew) but is
	// older than the consumed step, so it is a replay.
	if err := a.Verify(ctx, "alice", codeFor(t, enrolled, base)); !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("Verify old step: err = %v, want ErrCodeUsed", err)
	}
	// A code from two steps ahead is outside the acceptance window.
	if err := a.Verify(ctx, "alice", codeFor(t, enrolled, base+90)); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Verify +2 steps: err = %v, want ErrInvalidCode", err)
	}
}

func TestVerifyZeroSkew(t *testing.T) {
	ctx := context.Background()
	a, clock := newTestAuth(t, NewMemoryStore(), WithSkew(0))
	enrolled := enrollAndActivate(t, a, clock, "alice")
	base := clock.Now().Unix()

	if err := a.Verify(ctx, "alice", codeFor(t, enrolled, base+30)); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("+1 step with skew 0: err = %v, want ErrInvalidCode", err)
	}
	clock.Advance(30 * time.Second)
	if err := a.Verify(ctx, "alice", codeFor(t, enrolled, base+30)); err != nil {
		t.Fatalf("current step with skew 0: %v", err)
	}
}

// TestVerifyLaggingClientConsumesOlderStep checks the oldest-first ordering:
// a client one step behind consumes the older step, leaving the current step
// available later.
func TestVerifyLaggingClientConsumesOlderStep(t *testing.T) {
	ctx := context.Background()
	a, clock := newTestAuth(t, NewMemoryStore())
	enrolled := enrollAndActivate(t, a, clock, "alice")
	base := clock.Now().Unix()

	clock.Advance(60 * time.Second)
	lagging := codeFor(t, enrolled, base+30)
	current := codeFor(t, enrolled, base+60)
	if lagging == current {
		t.Skip("codes collide for this secret")
	}
	if err := a.Verify(ctx, "alice", lagging); err != nil {
		t.Fatalf("Verify lagging code: %v", err)
	}
	if err := a.Verify(ctx, "alice", current); err != nil {
		t.Fatalf("Verify current code after lagging one: %v", err)
	}
}

func TestVerifyReplay(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)
	enrolled := enrollAndActivate(t, a, clock, "alice")

	code := codeFor(t, enrolled, clock.Now().Unix()+30)
	clock.Advance(30 * time.Second)
	if err := a.Verify(ctx, "alice", code); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	revision, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := a.Verify(ctx, "alice", code); !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("replay: err = %v, want ErrCodeUsed", err)
	}
	after, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Revision != revision.Revision {
		t.Fatalf("a rejected replay advanced the revision: %d -> %d", revision.Revision, after.Revision)
	}
}

func TestVerifyInvalidCodeDoesNotWrite(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)
	enrollAndActivate(t, a, clock, "alice")

	before, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	bad := []string{"", "12345", "1234567", "abcdef", "１２３４５６", " 123456", "12345\n", "-12345", "000000"}
	for _, code := range bad {
		err := a.Verify(ctx, "alice", code)
		if !errors.Is(err, ErrInvalidCode) {
			t.Errorf("Verify(%q): err = %v, want ErrInvalidCode", code, err)
		}
	}
	after, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Revision != before.Revision || after.LastUsedStep != before.LastUsedStep {
		t.Fatalf("failed verification mutated the credential: %+v -> %+v", before, after)
	}
}

func TestVerifyUnknownAndPending(t *testing.T) {
	ctx := context.Background()
	a, _ := newTestAuth(t, NewMemoryStore())
	if err := a.Verify(ctx, "ghost", "123456"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Verify unknown: err = %v, want ErrNotEnrolled", err)
	}
	if _, err := a.Enroll(ctx, "alice", "alice"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := a.Verify(ctx, "alice", "123456"); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("Verify pending: err = %v, want ErrNotEnabled", err)
	}
}

func TestStatusUnknown(t *testing.T) {
	a, _ := newTestAuth(t, NewMemoryStore())
	if _, err := a.Status(context.Background(), "ghost"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Status unknown: err = %v, want ErrNotEnrolled", err)
	}
}

func TestDisable(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)

	if err := a.Disable(ctx, "ghost"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Disable unknown: err = %v, want ErrNotEnrolled", err)
	}
	enrollAndActivate(t, a, clock, "alice")
	if err := a.Disable(ctx, "alice"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if _, err := a.Status(ctx, "alice"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Status after Disable: err = %v, want ErrNotEnrolled", err)
	}
	if err := a.Verify(ctx, "alice", "123456"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Verify after Disable: err = %v, want ErrNotEnrolled", err)
	}

	// Disabling a pending enrollment works too.
	if _, err := a.Enroll(ctx, "bob", "bob"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := a.Disable(ctx, "bob"); err != nil {
		t.Fatalf("Disable pending: %v", err)
	}
}

// TestConcurrentVerifySameCode has two goroutines submit the same valid code:
// exactly one succeeds, the other sees ErrCodeUsed.
func TestConcurrentVerifySameCode(t *testing.T) {
	ctx := context.Background()
	a, clock := newTestAuth(t, NewMemoryStore())
	enrolled := enrollAndActivate(t, a, clock, "alice")
	clock.Advance(30 * time.Second)
	code := codeFor(t, enrolled, clock.Now().Unix())

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = a.Verify(ctx, "alice", code)
		}(i)
	}
	close(start)
	wg.Wait()

	success, used := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrCodeUsed):
			used++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if success != 1 || used != goroutines-1 {
		t.Fatalf("success=%d used=%d, want 1 and %d", success, used, goroutines-1)
	}
}

// faultyStore decorates a Store with programmable failures.
type faultyStore struct {
	Store
	getErr    error
	createErr error
	updateErr error
	deleteErr error
	// updateAttempts, when > 0, makes this many Updates fail with
	// ErrConflict before delegating.
	updateAttempts int
	updateCount    int
}

func (s *faultyStore) Get(ctx context.Context, userID string) (Credential, error) {
	if s.getErr != nil {
		return Credential{}, s.getErr
	}
	return s.Store.Get(ctx, userID)
}

func (s *faultyStore) Create(ctx context.Context, c Credential) error {
	if s.createErr != nil {
		return s.createErr
	}
	return s.Store.Create(ctx, c)
}

func (s *faultyStore) Update(ctx context.Context, c Credential) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	if s.updateCount < s.updateAttempts {
		s.updateCount++
		return ErrConflict
	}
	return s.Store.Update(ctx, c)
}

func (s *faultyStore) Delete(ctx context.Context, userID string, revision uint64) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.Store.Delete(ctx, userID, revision)
}

// TestStoreErrorsAreWrappedNotMapped checks that storage failures keep their
// identity instead of turning into auth sentinels.
func TestStoreErrorsAreWrappedNotMapped(t *testing.T) {
	ctx := context.Background()
	ops := []struct {
		name string
		call func(*Authenticator) error
	}{
		{"Enroll", func(a *Authenticator) error { _, err := a.Enroll(ctx, "alice", "alice"); return err }},
		{"Activate", func(a *Authenticator) error { return a.Activate(ctx, "alice", "123456") }},
		{"Verify", func(a *Authenticator) error { return a.Verify(ctx, "alice", "123456") }},
		{"Status", func(a *Authenticator) error { _, err := a.Status(ctx, "alice"); return err }},
		{"Disable", func(a *Authenticator) error { return a.Disable(ctx, "alice") }},
	}
	for _, op := range ops {
		t.Run(op.name+" Get", func(t *testing.T) {
			store := &faultyStore{Store: NewMemoryStore(), getErr: errStoreBoom}
			a, _ := newTestAuth(t, store)
			err := op.call(a)
			if !errors.Is(err, errStoreBoom) {
				t.Fatalf("err = %v, want errStoreBoom", err)
			}
			for _, sentinel := range []error{ErrNotEnrolled, ErrInvalidCode, ErrAlreadyEnabled, ErrNotEnabled, ErrCodeUsed, ErrEnrollmentExpired, ErrConflict} {
				if errors.Is(err, sentinel) {
					t.Fatalf("store error was mapped onto %v", sentinel)
				}
			}
		})
	}

	t.Run("Create", func(t *testing.T) {
		store := &faultyStore{Store: NewMemoryStore(), createErr: errStoreBoom}
		a, _ := newTestAuth(t, store)
		if _, err := a.Enroll(ctx, "alice", "alice"); !errors.Is(err, errStoreBoom) {
			t.Fatalf("err = %v, want errStoreBoom", err)
		}
	})
	t.Run("Update", func(t *testing.T) {
		store := &faultyStore{Store: NewMemoryStore(), updateErr: errStoreBoom}
		a, clock := newTestAuth(t, store)
		enrolled, err := a.Enroll(ctx, "alice", "alice")
		if err != nil {
			t.Fatalf("Enroll: %v", err)
		}
		if err := a.Activate(ctx, "alice", codeFor(t, enrolled, clock.Now().Unix())); !errors.Is(err, errStoreBoom) {
			t.Fatalf("Activate: err = %v, want errStoreBoom", err)
		}
	})
	t.Run("Delete", func(t *testing.T) {
		store := &faultyStore{Store: NewMemoryStore(), deleteErr: errStoreBoom}
		a, clock := newTestAuth(t, store)
		enrollAndActivate(t, a, clock, "alice")
		if err := a.Disable(ctx, "alice"); !errors.Is(err, errStoreBoom) {
			t.Fatalf("Disable: err = %v, want errStoreBoom", err)
		}
	})
}

// TestVerifyRetriesOnConflict makes the store lose the first two optimistic
// locks; Verify must re-read and succeed rather than surfacing ErrConflict.
func TestVerifyRetriesOnConflict(t *testing.T) {
	ctx := context.Background()
	inner := NewMemoryStore()
	store := &faultyStore{Store: inner, updateAttempts: 2}
	a, clock := newTestAuth(t, store)
	enrolled := enrollAndActivate(t, a, clock, "alice")
	clock.Advance(30 * time.Second)
	code := codeFor(t, enrolled, clock.Now().Unix())

	if err := a.Verify(ctx, "alice", code); err != nil {
		t.Fatalf("Verify with conflicts: %v", err)
	}
}

// TestVerifyConflictBudgetIsBounded makes every Update conflict; the result
// must be a retryable error, never ErrConflict itself.
func TestVerifyConflictBudgetIsBounded(t *testing.T) {
	ctx := context.Background()
	store := &faultyStore{Store: NewMemoryStore()}
	a, clock := newTestAuth(t, store)
	enrolled := enrollAndActivate(t, a, clock, "alice")
	// Fail every Update from here on.
	store.updateAttempts = 1 << 20
	clock.Advance(30 * time.Second)
	code := codeFor(t, enrolled, clock.Now().Unix())

	err := a.Verify(ctx, "alice", code)
	if err == nil {
		t.Fatal("Verify succeeded despite permanent conflicts")
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrInvalidCode) || errors.Is(err, ErrCodeUsed) {
		t.Fatalf("err = %v, want a dedicated retryable error", err)
	}
	if !errors.Is(err, errConflictRetry) {
		t.Fatalf("err = %v, want errConflictRetry", err)
	}
}

// TestActivateConflictThenReplay covers the race the design calls out: a
// competing activation wins, our retry re-reads an active credential and
// must report ErrCodeUsed rather than a blank success or ErrConflict.
func TestActivateConflictThenReplay(t *testing.T) {
	ctx := context.Background()
	inner := NewMemoryStore()
	store := &faultyStore{Store: inner}
	a, clock := newTestAuth(t, store)
	enrolled, err := a.Enroll(ctx, "alice", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code := codeFor(t, enrolled, clock.Now().Unix())

	// Simulate the competing activation directly against the inner store.
	cur, err := inner.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	cur.State = StateActive
	cur.LastUsedStep = stepAt(clock.Now().Unix(), DefaultPeriod)
	cur.EnrollmentExpiresAt = time.Time{}
	if err := inner.Update(ctx, cur); err != nil {
		t.Fatalf("competing Update: %v", err)
	}

	// Activate now re-reads an active credential that consumed this step.
	if err := a.Activate(ctx, "alice", code); !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("Activate after a competing activation: err = %v, want ErrCodeUsed", err)
	}
	// A different code on an active credential is a plain double activation.
	if err := a.Activate(ctx, "alice", "000000"); !errors.Is(err, ErrAlreadyEnabled) {
		t.Fatalf("Activate active credential with another code: err = %v, want ErrAlreadyEnabled", err)
	}
}

// TestVerifyConflictAfterCompetingConsume checks the loser of a Verify race
// ends in ErrCodeUsed.
func TestVerifyConflictAfterCompetingConsume(t *testing.T) {
	ctx := context.Background()
	inner := NewMemoryStore()
	store := &faultyStore{Store: inner, updateAttempts: 1}
	a, clock := newTestAuth(t, store)
	enrolled := enrollAndActivate(t, a, clock, "alice")
	clock.Advance(30 * time.Second)
	code := codeFor(t, enrolled, clock.Now().Unix())
	step := stepAt(clock.Now().Unix(), DefaultPeriod)

	// A competing verifier consumes the step.
	cur, err := inner.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	cur.LastUsedStep = step
	if err := inner.Update(ctx, cur); err != nil {
		t.Fatalf("competing Update: %v", err)
	}

	if err := a.Verify(ctx, "alice", code); !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("Verify after a competing consume: err = %v, want ErrCodeUsed", err)
	}
}

func TestEnrollCreateConflictRetries(t *testing.T) {
	ctx := context.Background()
	store := &faultyStore{Store: NewMemoryStore()}
	a, _ := newTestAuth(t, store)

	// Pre-create the row so the first Enroll's Create conflicts; Enroll must
	// re-read, see pending and rotate instead of failing.
	if _, err := a.Enroll(ctx, "alice", "alice"); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	if _, err := a.Enroll(ctx, "alice", "alice"); err != nil {
		t.Fatalf("second Enroll: %v", err)
	}
}

// TestEnrollRotateConflictExhausted makes every Update during the rotate
// path conflict: the retry budget must expire with a retryable error.
func TestEnrollRotateConflictExhausted(t *testing.T) {
	ctx := context.Background()
	store := &faultyStore{Store: NewMemoryStore()}
	a, _ := newTestAuth(t, store)
	if _, err := a.Enroll(ctx, "alice", "alice"); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	store.updateAttempts = 1 << 20
	if _, err := a.Enroll(ctx, "alice", "alice"); !errors.Is(err, errConflictRetry) {
		t.Fatalf("re-Enroll under permanent conflicts: err = %v, want errConflictRetry", err)
	}
}

func TestEnrollCreateConflictExhausted(t *testing.T) {
	ctx := context.Background()
	// Create always conflicts while Get always reports NotFound: the retry
	// budget must run out with a retryable error, not ErrConflict.
	store := &alwaysConflictCreateStore{}
	a, err := New(store, testKey(t), WithIssuer(testIssuer))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = a.Enroll(ctx, "alice", "alice")
	if !errors.Is(err, errConflictRetry) {
		t.Fatalf("err = %v, want errConflictRetry", err)
	}
}

type alwaysConflictCreateStore struct{ MemoryStore }

func (s *alwaysConflictCreateStore) Create(context.Context, Credential) error { return ErrConflict }

func TestRandomSourceFailure(t *testing.T) {
	ctx := context.Background()
	a, err := New(NewMemoryStore(), testKey(t), WithIssuer(testIssuer), WithRand(failingReader{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Enroll(ctx, "alice", "alice"); !errors.Is(err, errReaderBoom) {
		t.Fatalf("Enroll with failing rand: err = %v, want errReaderBoom", err)
	}
}

func TestDecryptFailureSurfaces(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)
	enrolled := enrollAndActivate(t, a, clock, "alice")

	cur, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	cur.EncryptedSecret[len(cur.EncryptedSecret)-1] ^= 0xff
	if err := store.Update(ctx, cur); err != nil {
		t.Fatalf("Update: %v", err)
	}

	err = a.Verify(ctx, "alice", codeFor(t, enrolled, clock.Now().Unix()+30))
	if err == nil {
		t.Fatal("Verify succeeded with a corrupted secret")
	}
	if errors.Is(err, ErrInvalidCode) || errors.Is(err, ErrCodeUsed) {
		t.Fatalf("decrypt failure was mapped onto an auth sentinel: %v", err)
	}
}

// TestSecretNeverReturned greps every public output path for the plaintext
// secret.
func TestSecretNeverReturned(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, _ := newTestAuth(t, store)
	enrolled, err := a.Enroll(ctx, "alice", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	secret := decodeSecret(t, enrolled)

	state, err := a.Status(ctx, "alice")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if strings.Contains(string(state), string(secret)) {
		t.Fatal("Status leaked the secret")
	}
	stored, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Contains(string(stored.EncryptedSecret), string(secret)) {
		t.Fatal("stored ciphertext contains the plaintext secret")
	}
}

func TestContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a, clock := newTestAuth(t, NewMemoryStore())
	enrolled, err := a.Enroll(context.Background(), "alice", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, err := a.Enroll(ctx, "bob", "bob"); !errors.Is(err, context.Canceled) {
		t.Errorf("Enroll: err = %v, want context.Canceled", err)
	}
	if err := a.Activate(ctx, "alice", codeFor(t, enrolled, clock.Now().Unix())); !errors.Is(err, context.Canceled) {
		t.Errorf("Activate: err = %v, want context.Canceled", err)
	}
	if err := a.Verify(ctx, "alice", "123456"); !errors.Is(err, context.Canceled) {
		t.Errorf("Verify: err = %v, want context.Canceled", err)
	}
	if _, err := a.Status(ctx, "alice"); !errors.Is(err, context.Canceled) {
		t.Errorf("Status: err = %v, want context.Canceled", err)
	}
	if err := a.Disable(ctx, "alice"); !errors.Is(err, context.Canceled) {
		t.Errorf("Disable: err = %v, want context.Canceled", err)
	}
}

// TestVerifyTwiceAcrossSteps consumes consecutive steps: each success moves
// LastUsedStep forward exactly once.
func TestVerifyAcrossSteps(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)
	enrolled := enrollAndActivate(t, a, clock, "alice")
	base := clock.Now().Unix()

	for i := 1; i <= 3; i++ {
		clock.Advance(30 * time.Second)
		if err := a.Verify(ctx, "alice", codeFor(t, enrolled, base+int64(i)*30)); err != nil {
			t.Fatalf("Verify step +%d: %v", i, err)
		}
		cur, err := store.Get(ctx, "alice")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		want := stepAt(base+int64(i)*30, DefaultPeriod)
		if cur.LastUsedStep != want {
			t.Fatalf("LastUsedStep = %d, want %d", cur.LastUsedStep, want)
		}
	}
}

func TestUnknownStoredState(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, _ := newTestAuth(t, store)
	if err := store.Create(ctx, Credential{UserID: "alice", State: "bogus", Revision: 0}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := a.Status(ctx, "alice"); err == nil || errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Status with unknown state: err = %v", err)
	}
	if err := a.Verify(ctx, "alice", "123456"); err == nil {
		t.Fatal("Verify with unknown state succeeded")
	}
	if err := a.Activate(ctx, "alice", "123456"); err == nil {
		t.Fatal("Activate with unknown state succeeded")
	}
	if _, err := a.Enroll(ctx, "alice", "alice"); err == nil {
		t.Fatal("Enroll with unknown state succeeded")
	}
}

// TestEnrollDeleteRace mocks a store where Delete reports a revision
// conflict; Disable must not silently pretend success.
func TestDisableConflictIsRetryableError(t *testing.T) {
	ctx := context.Background()
	store := &faultyStore{Store: NewMemoryStore(), deleteErr: ErrConflict}
	a, clock := newTestAuth(t, store)
	enrollAndActivate(t, a, clock, "alice")
	err := a.Disable(ctx, "alice")
	if !errors.Is(err, errConflictRetry) {
		t.Fatalf("err = %v, want errConflictRetry", err)
	}
}

// TestConcurrentActivateSameCode races several activations of the same code:
// exactly one wins, the rest must report ErrCodeUsed, not ErrConflict.
func TestConcurrentActivateSameCode(t *testing.T) {
	ctx := context.Background()
	a, clock := newTestAuth(t, NewMemoryStore())
	enrolled, err := a.Enroll(ctx, "alice", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	code := codeFor(t, enrolled, clock.Now().Unix())

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = a.Activate(ctx, "alice", code)
		}(i)
	}
	close(start)
	wg.Wait()

	success, used := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrCodeUsed):
			used++
		default:
			t.Fatalf("unexpected error from a concurrent Activate: %v", err)
		}
	}
	if success != 1 || used != goroutines-1 {
		t.Fatalf("success=%d used=%d, want 1 and %d", success, used, goroutines-1)
	}
	state, err := a.Status(ctx, "alice")
	if err != nil || state != StateActive {
		t.Fatalf("Status = %q, %v", state, err)
	}
}

// TestKeyIsCopied proves New does not retain the caller's key slice: mutating
// it afterwards must not corrupt seal/open.
func TestKeyIsCopied(t *testing.T) {
	ctx := context.Background()
	key := testKey(t)
	store := NewMemoryStore()
	a, err := New(store, key, WithIssuer(testIssuer), WithNow(newTestClock(1_700_000_000).Now))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := range key {
		key[i] = 0
	}
	clock := newTestClock(1_700_000_000)
	enrolled, err := a.Enroll(ctx, "alice", "alice")
	if err != nil {
		t.Fatalf("Enroll after key mutation: %v", err)
	}
	// The clock injected above is fixed at the same instant as this one.
	if err := a.Activate(ctx, "alice", codeFor(t, enrolled, clock.Now().Unix())); err != nil {
		t.Fatalf("Activate after key mutation: %v", err)
	}
}

// TestSecretsAreRandom makes sure two enrollments never share a secret when
// the default crypto/rand source is in use.
func TestSecretsAreRandom(t *testing.T) {
	ctx := context.Background()
	a, _ := newTestAuth(t, NewMemoryStore())
	first, err := a.Enroll(ctx, "alice", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	second, err := a.Enroll(ctx, "bob", "bob")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if first.Secret == second.Secret {
		t.Fatal("two enrollments produced the same secret")
	}
}

// TestFaultyStoreNilContextGuard documents that a nil context is treated as
// "not cancelled" rather than crashing MemoryStore.
func TestMemoryStoreNilContext(t *testing.T) {
	s := NewMemoryStore()
	// A nil context would panic if the guard were missing.
	if err := s.Create(nil, newTestCredential("alice")); err != nil { //nolint:staticcheck // deliberate
		t.Fatalf("Create with nil context: %v", err)
	}
	if _, err := s.Get(nil, "alice"); err != nil { //nolint:staticcheck // deliberate
		t.Fatalf("Get with nil context: %v", err)
	}
}

func TestStoreCredentialFieldsAreConsistent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, _ := newTestAuth(t, store)
	if _, err := a.Enroll(ctx, "alice", "alice@example.com"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	cur, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if cur.Algorithm != AlgorithmSHA1 || cur.Digits != 6 || cur.Period != 30 {
		t.Fatalf("stored profile = %+v", cur)
	}
	if cur.UserID != "alice" {
		t.Fatalf("UserID = %q", cur.UserID)
	}
	if cur.LastUsedStep != -1 {
		t.Fatalf("LastUsedStep = %d, want -1 before activation", cur.LastUsedStep)
	}
	if cur.Revision != 1 {
		t.Fatalf("Revision = %d, want 1", cur.Revision)
	}
}

// TestStoredProfileFallback covers a credential whose stored digits/period
// are unusable: consume must fall back to the configured profile rather than
// dividing by zero or producing a value of the wrong length.
func TestStoredProfileFallback(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)
	enrolled := enrollAndActivate(t, a, clock, "alice")

	cur, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	cur.Digits = 0
	cur.Period = 0
	if err := store.Update(ctx, cur); err != nil {
		t.Fatalf("Update: %v", err)
	}
	clock.Advance(30 * time.Second)
	if err := a.Verify(ctx, "alice", codeFor(t, enrolled, clock.Now().Unix())); err != nil {
		t.Fatalf("Verify with an unusable stored profile: %v", err)
	}
}

// TestStepBoundaryAcceptance checks codes at the exact step boundaries, which
// is where off-by-one acceptance bugs surface.
func TestStepBoundaryAcceptance(t *testing.T) {
	ctx := context.Background()
	a, clock := newTestAuth(t, NewMemoryStore())
	enrolled := enrollAndActivate(t, a, clock, "alice")

	// Jump to the last second of a step and use the next step's code: with
	// skew 1 that is accepted.
	clock.Set(1_700_000_030) // step 56666667, second 0 of it
	step := stepAt(clock.Now().Unix(), DefaultPeriod)
	nextCode := codeAt(decodeSecret(t, enrolled), step+1, 6, sha1New)
	if err := a.Verify(ctx, "alice", nextCode); err != nil {
		t.Fatalf("Verify next-step code inside skew: %v", err)
	}
	if got, err := a.Status(ctx, "alice"); err != nil || got != StateActive {
		t.Fatalf("Status = %q, %v", got, err)
	}
}

func TestFormattingHelpers(t *testing.T) {
	if got := percentEncode("a b@c:d/e"); got != "a%20b%40c%3Ad%2Fe" {
		t.Fatalf("percentEncode = %q", got)
	}
	if got := percentEncode("safe-._~09AZaz"); got != "safe-._~09AZaz" {
		t.Fatalf("percentEncode escaped unreserved characters: %q", got)
	}
	uri, err := buildURI("My App", "bob@example.com", "ABCDEF", 6, 30)
	if err != nil {
		t.Fatalf("buildURI: %v", err)
	}
	want := "otpauth://totp/My%20App:bob%40example.com?secret=ABCDEF&issuer=My%20App&algorithm=SHA1&digits=6&period=30"
	if uri != want {
		t.Fatalf("URI =\n  %s\nwant\n  %s", uri, want)
	}
	if _, err := buildURI("a:b", "bob", "s", 6, 30); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("colon issuer: err = %v", err)
	}
}

func TestUnexpectedOptionInteraction(t *testing.T) {
	// Enroll must honour a custom TTL.
	a, clock := newTestAuth(t, NewMemoryStore(), WithEnrollmentTTL(time.Minute))
	enrolled, err := a.Enroll(context.Background(), "alice", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if got, want := enrolled.ExpiresAt, clock.Now().Add(time.Minute); !got.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", got, want)
	}
}

func ExampleAuthenticator() {
	store := NewMemoryStore() // development only
	key := make([]byte, KeySize)
	a, err := New(store, key, WithIssuer("example.com"))
	if err != nil {
		panic(err)
	}
	enrollment, err := a.Enroll(context.Background(), "alice", "alice@example.com")
	if err != nil {
		panic(err)
	}
	fmt.Println(enrollment.State, len(enrollment.Secret), enrollment.URI != "")
	// Output: pending 32 true
}

func TestExportedDefaults(t *testing.T) {
	if SecretSize != 20 {
		t.Errorf("SecretSize = %d, want 20", SecretSize)
	}
	if KeySize != 32 {
		t.Errorf("KeySize = %d, want 32", KeySize)
	}
	if DefaultPeriod != 30 || DefaultDigits != 6 || DefaultSkew != 1 {
		t.Errorf("profile defaults drifted: %d/%d/%d", DefaultPeriod, DefaultDigits, DefaultSkew)
	}
	if DefaultEnrollmentTTL != 10*time.Minute {
		t.Errorf("DefaultEnrollmentTTL = %s", DefaultEnrollmentTTL)
	}
	if DefaultAlgorithm != AlgorithmSHA1 {
		t.Errorf("DefaultAlgorithm = %q", DefaultAlgorithm)
	}
	if MaxSkew != 1 {
		t.Errorf("MaxSkew = %d, want 1", MaxSkew)
	}
}

// TestVerifyRejectsOlderStep covers a non-replay older code: after consuming
// step N, a code from step N-1 is out of the window once the clock advances
// far enough, and inside it reports ErrCodeUsed rather than being accepted.
func TestVerifyRejectsOlderStep(t *testing.T) {
	ctx := context.Background()
	a, clock := newTestAuth(t, NewMemoryStore())
	enrolled := enrollAndActivate(t, a, clock, "alice")
	base := clock.Now().Unix()

	// Consume step N.
	clock.Advance(30 * time.Second)
	current := codeFor(t, enrolled, base+30)
	if err := a.Verify(ctx, "alice", current); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Step N-1 is still in the window but older than the consumed step.
	if err := a.Verify(ctx, "alice", codeFor(t, enrolled, base)); !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("older step: err = %v, want ErrCodeUsed", err)
	}
	// Once the window has moved past it, it is simply invalid.
	clock.Advance(60 * time.Second)
	if err := a.Verify(ctx, "alice", codeFor(t, enrolled, base)); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("stale step: err = %v, want ErrInvalidCode", err)
	}
}

// TestFailedActivationKeepsPending checks that a wrong code leaves the
// pending credential, its secret and its revision untouched.
func TestFailedActivationKeepsPending(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	a, clock := newTestAuth(t, store)
	enrolled, err := a.Enroll(ctx, "alice", "alice")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	before, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := a.Activate(ctx, "alice", "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("Activate with a wrong code: err = %v, want ErrInvalidCode", err)
	}
	after, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Revision != before.Revision || after.State != StatePending || after.LastUsedStep != -1 {
		t.Fatalf("failed activation mutated the credential: %+v -> %+v", before, after)
	}
	// The correct code still works afterwards.
	if err := a.Activate(ctx, "alice", codeFor(t, enrolled, clock.Now().Unix())); err != nil {
		t.Fatalf("Activate after a failed attempt: %v", err)
	}
}
