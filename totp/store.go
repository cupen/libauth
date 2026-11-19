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
	// StatePending: a secret was issued but no valid code has confirmed it.
	// Verify refuses pending credentials; Activate turns one into active.
	StatePending State = "pending"

	// StateActive: codes are accepted by Verify.
	StateActive State = "active"
)

// Credential is one user's TOTP enrollment. The secret is stored encrypted;
// callers must treat EncryptedSecret as opaque bytes.
type Credential struct {
	UserID              string
	State               State
	EncryptedSecret     []byte
	Algorithm           Algorithm
	Digits              int
	Period              int
	EnrollmentExpiresAt time.Time
	// LastUsedStep is the highest step already consumed by a successful
	// Activate or Verify. -1 means no step has been consumed yet.
	LastUsedStep int64
	// Revision is the optimistic-locking version. Create requires 0 and
	// stores revision 1; every Update increments it.
	Revision uint64
}

// Clone returns a deep copy of the credential.
func (c Credential) Clone() Credential {
	out := c
	if c.EncryptedSecret != nil {
		out.EncryptedSecret = append([]byte(nil), c.EncryptedSecret...)
	}
	return out
}

// Store persists TOTP credentials.
//
// Implementations must be safe for concurrent use, honor context
// cancellation, and return defensive copies: neither the caller nor the
// store may share the EncryptedSecret backing array.
//
// Atomicity contract for production stores:
//
//   - Create succeeds only when no credential exists for the user and
//     c.Revision is 0, storing it with Revision 1. A duplicate is
//     ErrConflict.
//   - Get returns ErrNotFound when no credential exists.
//   - Update replaces the whole row only when a credential for c.UserID
//     exists with exactly c.Revision, storing it with Revision+1. A missing
//     row or a revision mismatch is ErrConflict.
//   - Delete removes the row only when both userID and revision match.
//     A missing row or a revision mismatch is ErrConflict.
//
// A SQL implementation would use UPDATE ... WHERE user_id = ? AND
// revision = ?, checking the affected-row count. A MongoDB implementation
// would use replaceOne with a revision filter and looked-up document
// versioning. Either way the comparison and the write must be one atomic
// operation.
type Store interface {
	Create(ctx context.Context, c Credential) error
	Get(ctx context.Context, userID string) (Credential, error)
	Update(ctx context.Context, c Credential) error
	Delete(ctx context.Context, userID string, revision uint64) error
}

// MemoryStore is a thread-safe in-memory Store for development and tests.
// It is not durable and should not be used in production.
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

// Create implements Store.
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

// Get implements Store.
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

// Update implements Store.
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

// Delete implements Store.
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
