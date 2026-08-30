package branca

import "errors"

// Sentinel errors returned by sealing and opening. Errors from Open wrap
// one of these, so callers branch with errors.Is:
//
//	if errors.Is(err, branca.ErrTokenExpired) { ... }
var (
	// ErrTokenMalformed means the token is not a well-formed branca token:
	// invalid base62, too short, or a version byte other than 0xBA.
	ErrTokenMalformed = errors.New("libauth: token is malformed")

	// ErrTokenInvalid means XChaCha20-Poly1305 authentication failed: the
	// token was tampered with, or was sealed with a different key. AEAD
	// cannot distinguish the two, and neither should callers.
	ErrTokenInvalid = errors.New("libauth: token failed authentication")

	// ErrTokenExpired means the token's (authenticated) timestamp plus the
	// TTL passed to Open lies in the past. The check runs after successful
	// decryption, as the spec requires.
	ErrTokenExpired = errors.New("libauth: token has expired")

	// ErrTokenWithoutSubject means a token's payload has no "sub" member,
	// so it names no user.
	ErrTokenWithoutSubject = errors.New("libauth: token has no sub claim")

	// ErrMissingTTL is returned by VerifyBearer when the codec has no TTL
	// configured. Bearer tokens must not be accepted without an age bound.
	ErrMissingTTL = errors.New("libauth: bearer verification requires a TTL (configure WithTTL)")

	// ErrInvalidKey means the key is not exactly 32 bytes.
	ErrInvalidKey = errors.New("libauth: invalid key")
)
