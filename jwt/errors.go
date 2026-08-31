package jwt

import "errors"

// Sentinel errors returned by signing and verification. Errors from Verify
// wrap one of these, so callers branch with errors.Is:
//
//	if errors.Is(err, jwt.ErrTokenExpired) { ... }
var (
	// ErrTokenMalformed means the token is not a well-formed compact JWS:
	// wrong number of segments, bad base64url, or non-JSON header/payload.
	ErrTokenMalformed = errors.New("libauth: token is malformed")

	// ErrTokenBadSignature means the signature does not match the token
	// contents (wrong key or tampered token).
	ErrTokenBadSignature = errors.New("libauth: token signature is invalid")

	// ErrTokenExpired means the exp claim lies in the past (beyond leeway).
	ErrTokenExpired = errors.New("libauth: token has expired")

	// ErrTokenNotYetValid means the nbf claim lies in the future.
	ErrTokenNotYetValid = errors.New("libauth: token is not valid yet")

	// ErrTokenIssuedInFuture means the iat claim lies in the future.
	ErrTokenIssuedInFuture = errors.New("libauth: token is issued in the future")

	// ErrAlgMismatch means the token's alg header does not match the
	// verifier's pinned algorithm. This is what makes "none" and
	// cross-algorithm confusion impossible.
	ErrAlgMismatch = errors.New("libauth: token algorithm does not match the verifier")

	// ErrUnexpectedTyp means the token carries a typ header that is not
	// JWT (or application/jwt).
	ErrUnexpectedTyp = errors.New("libauth: token has an unexpected typ header")

	// ErrUnsupportedCrit means the token requests critical header extensions
	// this implementation does not support (it supports none).
	ErrUnsupportedCrit = errors.New("libauth: token has unsupported critical headers")

	// ErrMissingExpiration is returned by Sign when the claims carry no
	// ExpiresAt and no default TTL is configured. Tokens that never expire
	// cannot be created by accident.
	ErrMissingExpiration = errors.New("libauth: claims must carry an expiration (set ExpiresAt or configure WithTTL)")

	// ErrReservedClaim is returned when Extra claims collide with a
	// registered claim name (sub, iss, aud, jti, iat, exp, nbf).
	ErrReservedClaim = errors.New("libauth: extra claim collides with a registered claim")

	// ErrIssuerMismatch means the token's iss differs from the expected
	// issuer configured on the verifier.
	ErrIssuerMismatch = errors.New("libauth: token issuer does not match")

	// ErrAudienceMismatch means the token's aud does not contain the
	// expected audience configured on the verifier.
	ErrAudienceMismatch = errors.New("libauth: token audience does not match")

	// ErrInvalidKey means the key material has the wrong shape or size.
	ErrInvalidKey = errors.New("libauth: invalid key")
)
