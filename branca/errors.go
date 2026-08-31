package branca

import "errors"

// Sentinel errors returned by Decode. Errors wrap one of these, so
// callers branch with errors.Is:
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
	// TTL passed to Decode lies in the past. The check runs after
	// successful decryption, as the spec requires.
	ErrTokenExpired = errors.New("libauth: token has expired")

	// ErrInvalidKey means the key is not exactly 32 bytes.
	ErrInvalidKey = errors.New("libauth: invalid key")
)
