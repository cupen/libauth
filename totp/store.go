package totp

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// State is the lifecycle state of a TOTP credential.
type State string

const (
	StatePending State = "pending"
	StateActive  State = "active"
)

// Credential is one user's TOTP enrollment. EncryptedSecret is opaque.
type Credential struct {
	UserID              string
	State               State
	EncryptedSecret     []byte
	Algorithm           Algorithm
	Digits              int
	Period              int
	EnrollmentExpiresAt time.Time
	// LastUsedStep is the highest consumed step; -1 means none.
	LastUsedStep int64
	// Revision is the optimistic-locking version.
	Revision uint64
}

func (c Credential) Clone() Credential {
	out := c
	if c.EncryptedSecret != nil {
		out.EncryptedSecret = append([]byte(nil), c.EncryptedSecret...)
	}
	return out
}

// Store persists TOTP credentials. Implementations must be safe for
// concurrent use, honor context cancellation and return defensive copies.
//
// Atomicity contract:
//   - Create succeeds only when no credential exists and c.Revision is 0,
//     storing Revision 1; a duplicate is ErrConflict.
//   - Get returns ErrNotFound when absent.
//   - Update replaces the row only when c.Revision matches, storing
//     Revision+1; a missing row or mismatch is ErrConflict.
//   - Delete removes the row only when userID and revision both match.
type Store interface {
	Create(ctx context.Context, c Credential) error
	Get(ctx context.Context, userID string) (Credential, error)
	Update(ctx context.Context, c Credential) error
	Delete(ctx context.Context, userID string, revision uint64) error
}

// MemoryStore is a thread-safe, non-durable Store for development and tests.
type MemoryStore struct {
	mu   sync.Mutex
	rows map[string]Credential
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{rows: make(map[string]Credential)}
}

func (m *MemoryStore) ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (m *MemoryStore) Create(ctx context.Context, c Credential) error {
	if err := m.ctxErr(ctx); err != nil {
		return err
	}
	if c.Revision != 0 {
		return fmt.Errorf("%w: Create requires revision 0, got %d", ErrConflict, c.Revision)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctxErr(ctx); err != nil {
		return err
	}
	if _, ok := m.rows[c.UserID]; ok {
		return fmt.Errorf("%w: credential for %q already exists", ErrConflict, c.UserID)
	}
	stored := c.Clone()
	stored.Revision = 1
	m.rows[c.UserID] = stored
	return nil
}

func (m *MemoryStore) Get(ctx context.Context, userID string) (Credential, error) {
	if err := m.ctxErr(ctx); err != nil {
		return Credential{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctxErr(ctx); err != nil {
		return Credential{}, err
	}
	c, ok := m.rows[userID]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return c.Clone(), nil
}

func (m *MemoryStore) Update(ctx context.Context, c Credential) error {
	if err := m.ctxErr(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctxErr(ctx); err != nil {
		return err
	}
	cur, ok := m.rows[c.UserID]
	if !ok || cur.Revision != c.Revision {
		return fmt.Errorf("%w: revision mismatch for %q", ErrConflict, c.UserID)
	}
	stored := c.Clone()
	stored.Revision = c.Revision + 1
	m.rows[c.UserID] = stored
	return nil
}

func (m *MemoryStore) Delete(ctx context.Context, userID string, revision uint64) error {
	if err := m.ctxErr(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ctxErr(ctx); err != nil {
		return err
	}
	cur, ok := m.rows[userID]
	if !ok || cur.Revision != revision {
		return fmt.Errorf("%w: revision mismatch for %q", ErrConflict, userID)
	}
	delete(m.rows, userID)
	return nil
}
