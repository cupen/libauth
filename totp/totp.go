package totp

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// maxConflictRetries bounds how many times an operation re-reads the
// credential after losing an optimistic-locking race. Concurrent operations
// converge within one or two rounds; the bound exists so a hot credential
// can never spin forever.
const maxConflictRetries = 3

// Enrollment is the one-time result of Enroll. Secret is returned exactly
// once and never again: losing it means the user must re-enroll.
type Enrollment struct {
	// State is always StatePending for a fresh enrollment.
	State State
	// Secret is the Base32 (no padding) shared secret, for manual entry or
	// QR rendering.
	Secret string
	// URI is the otpauth:// URI to render as a QR code.
	URI string
	// ExpiresAt is when Activate stops accepting codes.
	ExpiresAt time.Time
}

// Authenticator enrolls, activates, verifies and disables TOTP credentials.
// It is safe for concurrent use.
type Authenticator struct {
	store  Store
	cipher *secretCipher
	set    *settings
}

// New returns an Authenticator persisting to store and sealing secrets with
// the 32-byte encryptionKey. An issuer is required via WithIssuer; the other
// options default to the interoperable TOTP profile (SHA1, 6 digits, 30s
// steps, one step of skew).
func New(store Store, encryptionKey []byte, opts ...Option) (*Authenticator, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}
	set := newSettings(opts)
	if err := set.validate(); err != nil {
		return nil, err
	}
	cipher, err := newSecretCipher(encryptionKey, set.rand)
	if err != nil {
		return nil, err
	}
	return &Authenticator{store: store, cipher: cipher, set: set}, nil
}

// Enroll issues a new pending secret for userID.
//
// The secret is returned in the Enrollment only. Calling Enroll again while
// the credential is pending rotates the secret and resets the deadline;
// calling it while active returns ErrAlreadyEnabled (Disable first).
func (a *Authenticator) Enroll(ctx context.Context, userID, accountName string) (*Enrollment, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("%w: user ID is required", ErrInvalidConfig)
	}
	if strings.TrimSpace(accountName) == "" {
		return nil, fmt.Errorf("%w: account name is required", ErrInvalidConfig)
	}
	// Reject an ambiguous label before any randomness is consumed or any
	// state is written.
	if strings.ContainsRune(accountName, ':') {
		return nil, fmt.Errorf("%w: account name must not contain ':'", ErrInvalidConfig)
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}

	for attempt := 0; attempt < maxConflictRetries; attempt++ {
		cur, err := a.store.Get(ctx, userID)
		switch {
		case errors.Is(err, ErrNotFound):
			enrollment, cerr := a.create(ctx, userID, accountName)
			if errors.Is(cerr, ErrConflict) {
				continue
			}
			return enrollment, cerr
		case err != nil:
			return nil, err
		case cur.State == StateActive:
			return nil, fmt.Errorf("%w: user %q already has an active TOTP credential", ErrAlreadyEnabled, userID)
		case cur.State != StatePending:
			return nil, fmt.Errorf("libauth: credential for %q has unknown state %q", userID, cur.State)
		}

		enrollment, err := a.rotate(ctx, cur, accountName)
		if errors.Is(err, ErrConflict) {
			continue
		}
		return enrollment, err
	}
	return nil, errConflictRetry
}

func (a *Authenticator) create(ctx context.Context, userID, accountName string) (*Enrollment, error) {
	cred, enrollment, err := a.prepare(userID, accountName, 0)
	if err != nil {
		return nil, err
	}
	if err := a.store.Create(ctx, cred); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return enrollment, nil
}

func (a *Authenticator) rotate(ctx context.Context, cur Credential, accountName string) (*Enrollment, error) {
	cred, enrollment, err := a.prepare(cur.UserID, accountName, cur.Revision)
	if err != nil {
		return nil, err
	}
	if err := a.store.Update(ctx, cred); err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return enrollment, nil
}

func (a *Authenticator) prepare(userID, accountName string, revision uint64) (Credential, *Enrollment, error) {
	secret := make([]byte, SecretSize)
	if _, err := io.ReadFull(a.set.rand, secret); err != nil {
		return Credential{}, nil, fmt.Errorf("libauth: generate TOTP secret: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)

	sealed, err := a.cipher.seal(userID, secret)
	if err != nil {
		return Credential{}, nil, err
	}
	uri, err := buildURI(a.set.issuer, accountName, encoded, a.set.digits, a.set.period)
	if err != nil {
		return Credential{}, nil, err
	}
	expiresAt := a.set.now().Add(a.set.ttl)

	cred := Credential{
		UserID:              userID,
		State:               StatePending,
		EncryptedSecret:     sealed,
		Algorithm:           a.set.algorithm,
		Digits:              a.set.digits,
		Period:              a.set.period,
		EnrollmentExpiresAt: expiresAt,
		LastUsedStep:        -1,
		Revision:            revision,
	}
	return cred, &Enrollment{
		State:     StatePending,
		Secret:    encoded,
		URI:       uri,
		ExpiresAt: expiresAt,
	}, nil
}

// Activate confirms a pending enrollment with its first valid code and
// switches it to StateActive. The matching step is consumed, so the same
// code is rejected by Verify afterwards.
//
// An expired pending enrollment returns ErrEnrollmentExpired and is left in
// place. On an already-active credential the call reports ErrAlreadyEnabled,
// except when code is exactly the step the winning activation consumed: that
// is what the loser of a concurrent activation sees, and it reports
// ErrCodeUsed.
func (a *Authenticator) Activate(ctx context.Context, userID, code string) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	for attempt := 0; attempt < maxConflictRetries; attempt++ {
		cur, err := a.store.Get(ctx, userID)
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("%w: user %q", ErrNotEnrolled, userID)
		}
		if err != nil {
			return err
		}
		switch cur.State {
		case StatePending:
		case StateActive:
			if a.codeConsumed(userID, cur, code) {
				return fmt.Errorf("%w: user %q", ErrCodeUsed, userID)
			}
			return fmt.Errorf("%w: user %q", ErrAlreadyEnabled, userID)
		default:
			return fmt.Errorf("libauth: credential for %q has unknown state %q", userID, cur.State)
		}

		now := a.set.now()
		if now.After(cur.EnrollmentExpiresAt) {
			return fmt.Errorf("%w: user %q", ErrEnrollmentExpired, userID)
		}

		secret, err := a.cipher.open(userID, cur.EncryptedSecret)
		if err != nil {
			return err
		}
		step, err := a.consume(secret, cur, code)
		if err != nil {
			return err
		}

		activated := cur.Clone()
		activated.State = StateActive
		activated.EnrollmentExpiresAt = time.Time{}
		activated.LastUsedStep = step
		if err := a.store.Update(ctx, activated); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return err
		}
		return nil
	}
	return errConflictRetry
}

// Verify checks code against an active credential and advances the last-used
// step. It returns ErrNotEnabled while enrollment is pending, ErrCodeUsed for
// a replayed or older code, and ErrInvalidCode when no accepted step matches.
func (a *Authenticator) Verify(ctx context.Context, userID, code string) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	for attempt := 0; attempt < maxConflictRetries; attempt++ {
		cur, err := a.store.Get(ctx, userID)
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("%w: user %q", ErrNotEnrolled, userID)
		}
		if err != nil {
			return err
		}
		switch cur.State {
		case StateActive:
		case StatePending:
			return fmt.Errorf("%w: user %q", ErrNotEnabled, userID)
		default:
			return fmt.Errorf("libauth: credential for %q has unknown state %q", userID, cur.State)
		}

		secret, err := a.cipher.open(userID, cur.EncryptedSecret)
		if err != nil {
			return err
		}
		step, err := a.consume(secret, cur, code)
		if err != nil {
			return err
		}

		next := cur.Clone()
		next.LastUsedStep = step
		if err := a.store.Update(ctx, next); err != nil {
			if errors.Is(err, ErrConflict) {
				continue
			}
			return err
		}
		return nil
	}
	return errConflictRetry
}

// codeConsumed reports whether code is exactly the step already consumed by
// a successful activation. It sharpens the error the loser of a concurrent
// activation returns; a decryption or format failure simply reports false.
func (a *Authenticator) codeConsumed(userID string, cur Credential, code string) bool {
	secret, err := a.cipher.open(userID, cur.EncryptedSecret)
	if err != nil {
		return false
	}
	digits, period := a.profile(cur)
	normalized, ok := parseCode(code, digits)
	if !ok {
		return false
	}
	current := stepAt(a.set.now().Unix(), period)
	step, ok := matchStep(secret, normalized, current, a.set.skew, digits)
	return ok && step == cur.LastUsedStep
}

// profile resolves the per-credential digits/period, falling back to the
// configured profile when the stored values are unusable.
func (a *Authenticator) profile(cur Credential) (digits int, period int64) {
	digits = cur.Digits
	if digits < 1 || digits > 10 {
		digits = a.set.digits
	}
	period = int64(cur.Period)
	if period <= 0 {
		period = int64(a.set.period)
	}
	return digits, period
}

// consume validates code against cur's secret and returns the matching step.
// A match that is not strictly newer than LastUsedStep is a replay.
func (a *Authenticator) consume(secret []byte, cur Credential, code string) (int64, error) {
	digits, period := a.profile(cur)
	normalized, ok := parseCode(code, digits)
	if !ok {
		return 0, fmt.Errorf("%w: expected %d ASCII digits", ErrInvalidCode, digits)
	}

	current := stepAt(a.set.now().Unix(), period)
	step, ok := matchStep(secret, normalized, current, a.set.skew, digits)
	if !ok {
		return 0, ErrInvalidCode
	}
	if step <= cur.LastUsedStep {
		return 0, fmt.Errorf("%w: step %d was already consumed", ErrCodeUsed, step)
	}
	return step, nil
}

// Disable removes the credential. Delete is conditional on the revision read
// just before, so a concurrent change (a new enrollment, for instance) is
// never deleted by mistake: the conflict surfaces as a retryable error
// instead of a blind retry.
func (a *Authenticator) Disable(ctx context.Context, userID string) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	cur, err := a.store.Get(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return fmt.Errorf("%w: user %q", ErrNotEnrolled, userID)
	}
	if err != nil {
		return err
	}
	if err := a.store.Delete(ctx, userID, cur.Revision); err != nil {
		if errors.Is(err, ErrConflict) {
			return errConflictRetry
		}
		return err
	}
	return nil
}

// Status reports whether the user has a pending or active credential.
func (a *Authenticator) Status(ctx context.Context, userID string) (State, error) {
	if err := ctxErr(ctx); err != nil {
		return "", err
	}
	cur, err := a.store.Get(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return "", fmt.Errorf("%w: user %q", ErrNotEnrolled, userID)
	}
	if err != nil {
		return "", err
	}
	if cur.State != StatePending && cur.State != StateActive {
		return "", fmt.Errorf("libauth: credential for %q has unknown state %q", userID, cur.State)
	}
	return cur.State, nil
}

func ctxErr(ctx context.Context) error {
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

// compile-time assertion: Authenticator honours the approved method set.
var _ interface {
	Enroll(context.Context, string, string) (*Enrollment, error)
	Activate(context.Context, string, string) error
	Verify(context.Context, string, string) error
	Status(context.Context, string) (State, error)
	Disable(context.Context, string) error
} = (*Authenticator)(nil)
