// Sentinel errors returned by Decode. Errors wrap one of these, so
// callers branch with errors.Is.
package branca

import "errors"

var (
	// ErrTokenMalformed: not a well-formed branca token — invalid base62,
	// too short, or a version byte other than 0xBA.
	ErrTokenMalformed = errors.New("libauth: token is malformed")

	// ErrTokenInvalid: XChaCha20-Poly1305 authentication failed. AEAD
	// cannot distinguish tampering from a wrong key, and neither should
	// callers.
	ErrTokenInvalid = errors.New("libauth: token failed authentication")

	// ErrTokenExpired: token's authenticated timestamp plus the TTL passed
	// to Decode lies in the past. The check runs after successful
	// decryption, as the spec requires.
	ErrTokenExpired = errors.New("libauth: token has expired")

	ErrInvalidKey = errors.New("libauth: invalid key")
)