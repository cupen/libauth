// Sentinel errors returned by Authenticator methods and Store
// implementations. Callers branch with errors.Is.
package totp

import "errors"

var (
	// ErrNotEnrolled: the user has no TOTP credential.
	ErrNotEnrolled = errors.New("libauth: TOTP is not enrolled")

	// ErrAlreadyEnabled: Enroll or Activate was called while the credential
	// is already active. Disable it first to re-enroll.
	ErrAlreadyEnabled = errors.New("libauth: TOTP is already enabled")

	// ErrNotEnabled: Verify was called while enrollment is still pending.
	ErrNotEnabled = errors.New("libauth: TOTP is not enabled")

	// ErrInvalidCode: the submitted value is not a well-formed code of the
	// configured length, or it does not match any accepted step.
	ErrInvalidCode = errors.New("libauth: invalid TOTP code")

	// ErrCodeUsed: the submitted code matches the last step already
	// consumed. TOTP codes are single-use.
	ErrCodeUsed = errors.New("libauth: TOTP code has already been used")

	// ErrEnrollmentExpired: the pending enrollment's TTL has passed. The
	// pending credential is kept until the application disables it or calls
	// Enroll again.
	ErrEnrollmentExpired = errors.New("libauth: TOTP enrollment has expired")

	// ErrInvalidConfig: New rejected the encryption key or an option.
	ErrInvalidConfig = errors.New("libauth: invalid TOTP configuration")

	// ErrNotFound is returned by Store implementations when no credential
	// exists for the user. Authenticator methods map it to ErrNotEnrolled.
	ErrNotFound = errors.New("libauth: TOTP credential not found")

	// ErrConflict is returned by Store implementations when an optimistic
	// locking precondition fails (revision mismatch or duplicate create).
	// Authenticator methods retry and translate it; it is never the final
	// error of a normal operation.
	ErrConflict = errors.New("libauth: TOTP credential conflict")

	// errConflictRetry is reported when a Store stays contended for the
	// whole retry budget. It deliberately does not wrap ErrConflict, so
	// callers never have to treat a transient lock failure as a credential
	// conflict.
	errConflictRetry = errors.New("libauth: TOTP credential is changing concurrently, retry the request")
)
