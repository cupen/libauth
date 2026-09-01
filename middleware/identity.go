package middleware

import (
	"errors"
	"net/http"

	"github.com/cupen/libauth/model"
)

// IdentityFunc extracts the acting user's ID from a request. An error
// means the caller could not be identified (guards answer 401).
type IdentityFunc func(r *http.Request) (model.UserID, error)

// HeaderIdentity returns an IdentityFunc reading a header (default
// "X-User-ID"). For demos and internal services; wire your real auth
// (JWT, session, ...) here in production.
func HeaderIdentity(header string) IdentityFunc {
	if header == "" {
		header = "X-User-ID"
	}
	return func(r *http.Request) (model.UserID, error) {
		id := r.Header.Get(header)
		if id == "" {
			return "", errors.New("missing identity header " + header)
		}
		return id, nil
	}
}