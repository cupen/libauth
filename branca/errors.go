// Sentinel errors returned by Decode; errors wrap one of these, so callers
// branch with errors.Is.
package branca

import "errors"

var (
	ErrTokenMalformed = errors.New("libauth: token is malformed")
	ErrTokenInvalid   = errors.New("libauth: token failed authentication")
	ErrTokenExpired   = errors.New("libauth: token has expired")
	ErrInvalidKey     = errors.New("libauth: invalid key")
)
