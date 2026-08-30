package libauth

import (
	"errors"
	"net/http"
	"strings"
)

// ErrMissingBearerToken means the Authorization header carries no
// "Bearer <token>" credential.
var ErrMissingBearerToken = errors.New("libauth: missing bearer token")

// BearerVerifier verifies a bearer token and names the user it stands for.
// Both built-in token codecs satisfy it: *jwt.Verifier (signed JWTs, pure
// stdlib) and *branca.Codec (encrypted branca tokens, golang.org/x/crypto).
type BearerVerifier interface {
	// VerifyBearer returns the user ID (the token's sub claim) the token
	// names, or an error if the token is invalid, expired or anonymous.
	VerifyBearer(token string) (string, error)
}

// BearerIdentity returns an IdentityFunc that authenticates requests by
// verifying the token in "Authorization: Bearer <token>" with v. Build v
// with jwt.NewVerifierHS256 / jwt.NewVerifierEdDSA or branca.New — the jwt
// and branca subpackages hold the token APIs.
//
// The verified token's sub claim becomes the user ID. Roles and permissions
// are still resolved server-side by the Enforcer, so revoking a role takes
// effect on the next request without reissuing tokens.
//
//	mw, err := libauth.NewMiddleware(enforcer, libauth.BearerIdentity(verifier))
func BearerIdentity(v BearerVerifier) IdentityFunc {
	return func(r *http.Request) (string, error) {
		if r == nil {
			return "", ErrMissingBearerToken
		}
		h := r.Header.Get("Authorization")
		if len(h) <= len(bearerPrefix) || !strings.EqualFold(h[:len(bearerPrefix)], bearerPrefix) {
			return "", ErrMissingBearerToken
		}
		token := strings.TrimSpace(h[len(bearerPrefix):])
		if token == "" {
			return "", ErrMissingBearerToken
		}
		return v.VerifyBearer(token)
	}
}

const bearerPrefix = "bearer "
