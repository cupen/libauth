// Package totp implements RFC 6238 time-based one-time passwords (TOTP),
// using RFC 4226 HOTP as the underlying primitive. It is a standalone
// subpackage: it depends only on the Go standard library and does not
// touch the RBAC Store, User, JWT or middleware types.
//
// # Lifecycle
//
// A credential has two states:
//
//   - StatePending: Enroll issued a secret to show to the user exactly
//     once. Verify is not available yet.
//   - StateActive: Activate verified the first code. Subsequent login
//     attempts call Verify.
//
// Enroll on an active credential fails with ErrAlreadyEnabled; call
// Disable first to start over. Enroll on a pending credential issues a
// fresh secret and resets the enrollment deadline.
//
// Authenticator methods return sentinel errors (ErrNotEnrolled,
// ErrInvalidCode, ErrCodeUsed, ...) suitable for errors.Is. Store failures
// and crypto failures are wrapped with %w instead of being mapped onto the
// authentication sentinels.
//
// # Security
//
// Secrets are 20 bytes from crypto/rand, stored AES-256-GCM sealed under
// the 32-byte key passed to New, and never returned again after Enroll.
// Verification accepts at most one step of clock skew (configurable 0..1),
// advances a per-credential last-used step, rejects replay and old steps,
// and compares codes in constant time.
//
// The Authenticator does not implement the first authentication factor.
// Applications must verify the password (or other primary credential)
// before calling Activate or Verify, serve traffic over TLS, rate-limit
// attempts, provide recovery codes, and run any login challenge logic.
//
// MemoryStore is an in-memory reference implementation for development and
// tests only. Production deployments must supply a durable Store honoring
// the atomicity contract documented on the Store interface.
package totp
