// Package totp implements RFC 6238 time-based one-time passwords over
// RFC 4226 HOTP. It is standalone: stdlib only, no RBAC dependencies.
//
// A credential is StatePending after Enroll (the secret is shown exactly
// once) and StateActive after Activate confirms the first code. Secrets are
// 20 random bytes, stored AES-256-GCM sealed, and never returned again.
//
// The Authenticator is not a first factor: verify the password first, serve
// over TLS, rate-limit attempts and provide recovery codes. MemoryStore is
// for development and tests only; production needs a durable Store honoring
// the atomicity contract on the Store interface.
package totp
