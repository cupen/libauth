package middleware

import (
	"errors"
	"net/http"

	"github.com/cupen/libauth/model"
)

// IdentityFunc extracts the acting user's ID from a request; an error means
// the caller could not be identified.
type IdentityFunc func(r *http.Request) (model.UserID, error)

// HeaderIdentity reads the user ID from a header (default "X-User-ID"). It is
// meant for demos and internal services.
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
