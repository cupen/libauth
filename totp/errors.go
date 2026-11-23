// Sentinel errors returned by Authenticator methods and Store
// implementations; callers branch with errors.Is.
package totp

import "errors"

var (
	ErrNotEnrolled = errors.New("libauth: TOTP is not enrolled")

	// ErrAlreadyEnabled: the credential is active; Disable it to re-enroll.
	ErrAlreadyEnabled = errors.New("libauth: TOTP is already enabled")

	ErrNotEnabled  = errors.New("libauth: TOTP is not enabled")
	ErrInvalidCode = errors.New("libauth: invalid TOTP code")

	// ErrCodeUsed: TOTP codes are single-use.
	ErrCodeUsed = errors.New("libauth: TOTP code has already been used")

	ErrEnrollmentExpired = errors.New("libauth: TOTP enrollment has expired")
	ErrInvalidConfig     = errors.New("libauth: invalid TOTP configuration")

	// ErrNotFound is what Store implementations return when no credential
	// exists; Authenticator methods map it to ErrNotEnrolled.
	ErrNotFound = errors.New("libauth: TOTP credential not found")

	// ErrConflict signals a failed optimistic-locking precondition.
	ErrConflict = errors.New("libauth: TOTP credential conflict")

	// errConflictRetry is a persistent lock failure, deliberately not
	// wrapping ErrConflict.
	errConflictRetry = errors.New("libauth: TOTP credential is changing concurrently, retry the request")
)
