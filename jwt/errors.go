// Sentinel errors returned by signing and verification. Verify wraps one
// of these, so callers branch with errors.Is.
package jwt

import "errors"

var (
	// ErrTokenMalformed: not a well-formed compact JWS — wrong number of
	// segments, bad base64url, or non-JSON header/payload.
	ErrTokenMalformed = errors.New("libauth: token is malformed")

	ErrTokenBadSignature = errors.New("libauth: token signature is invalid")

	ErrTokenExpired        = errors.New("libauth: token has expired")
	ErrTokenNotYetValid    = errors.New("libauth: token is not valid yet")
	ErrTokenIssuedInFuture = errors.New("libauth: token is issued in the future")

	// ErrAlgMismatch: token's alg header does not match the verifier's
	// pinned algorithm. This makes "none" and cross-algorithm confusion
	// impossible.
	ErrAlgMismatch = errors.New("libauth: token algorithm does not match the verifier")

	ErrUnexpectedTyp   = errors.New("libauth: token has an unexpected typ header")
	ErrUnsupportedCrit = errors.New("libauth: token has unsupported critical headers")

	// ErrMissingExpiration: Sign refuses to issue a token without exp
	// unless a default TTL is configured.
	ErrMissingExpiration = errors.New("libauth: claims must carry an expiration (set ExpiresAt or configure WithTTL)")

	// ErrMissingSubject: Sign refuses to issue a token without sub. libauth
	// uses sub as the user ID; a token without it has nothing to
	// authenticate against downstream.
	ErrMissingSubject = errors.New("libauth: claims must carry a subject (set Claims.Subject)")

	ErrReservedClaim = errors.New("libauth: extra claim collides with a registered claim")
	ErrIssuerMismatch = errors.New("libauth: token issuer does not match")
	ErrAudienceMismatch = errors.New("libauth: token audience does not match")
	ErrInvalidKey = errors.New("libauth: invalid key")
)