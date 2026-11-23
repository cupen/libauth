// Sentinel errors returned by Encode and Decode. Errors wrap one of these,
// so callers branch with errors.Is.
package jwt

import "errors"

var (
	ErrTokenMalformed    = errors.New("libauth: token is malformed")
	ErrTokenBadSignature = errors.New("libauth: token signature is invalid")

	ErrTokenExpired        = errors.New("libauth: token has expired")
	ErrTokenNotYetValid    = errors.New("libauth: token is not valid yet")
	ErrTokenIssuedInFuture = errors.New("libauth: token is issued in the future")

	// ErrAlgMismatch pins the token's alg header to the verifier's algorithm.
	ErrAlgMismatch = errors.New("libauth: token algorithm does not match the verifier")

	ErrUnexpectedTyp   = errors.New("libauth: token has an unexpected typ header")
	ErrUnsupportedCrit = errors.New("libauth: token has unsupported critical headers")

	ErrMissingExpiration = errors.New("libauth: claims must carry an expiration (set ExpiresAt or configure WithTTL)")

	// ErrMissingSubject: libauth uses sub as the user ID.
	ErrMissingSubject = errors.New("libauth: claims must carry a subject (set Claims.Subject)")

	ErrReservedClaim    = errors.New("libauth: extra claim collides with a registered claim")
	ErrIssuerMismatch   = errors.New("libauth: token issuer does not match")
	ErrAudienceMismatch = errors.New("libauth: token audience does not match")
	ErrInvalidKey       = errors.New("libauth: invalid key")
)
