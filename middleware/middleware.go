// Package middleware provides net/http adapters for libauth: guards that
// identify the caller, run permission or role checks and inject the resolved
// user into the request context.
//
// Every guard works against the Authorizer interface; *libauth.Enforcer
// satisfies it out of the box.
package middleware

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

var ErrInvalidIdentityFunc = errors.New("libauth: identity func is required")

// Authorizer is the subset of the permission API the guards depend on.
type Authorizer interface {
	Check(id model.UserID, required model.Permission) error
	HasPermission(id model.UserID, required model.Permission) (bool, error)
	HasRole(id model.UserID, role model.RoleName) (bool, error)
	GetUser(id model.UserID) (*model.User, error)
}

// Middleware guards http.Handler chains with libauth checks.
type Middleware struct {
	manager  Authorizer
	identity IdentityFunc
	// OnError, when set, fully handles error responses. status is the
	// suggested HTTP status code (401, 403 or 500).
	OnError func(w http.ResponseWriter, r *http.Request, status int, err error)
}

// NewMiddleware builds middleware for the authorizer. A nil identity
// defaults to HeaderIdentity("").
func NewMiddleware(m Authorizer, identity IdentityFunc) (*Middleware, error) {
	if m == nil {
		return nil, ErrInvalidIdentityFunc
	}
	if identity == nil {
		identity = HeaderIdentity("")
	}
	return &Middleware{manager: m, identity: identity}, nil
}

func (mw *Middleware) authorize(w http.ResponseWriter, r *http.Request, perm model.Permission) (*model.User, bool) {
	u, ok := mw.identify(w, r)
	if !ok {
		return nil, false
	}
	return mw.pass(w, r, u, perm)
}

func (mw *Middleware) pass(w http.ResponseWriter, r *http.Request, u *model.User, perm model.Permission) (*model.User, bool) {
	err := mw.manager.Check(u.ID, perm)
	if err == nil {
		return u, true
	}
	status := http.StatusForbidden
	if errors.Is(err, store.ErrUserNotFound) {
		status = http.StatusUnauthorized
	}
	mw.fail(w, r, status, err)
	return nil, false
}

func (mw *Middleware) identify(w http.ResponseWriter, r *http.Request) (*model.User, bool) {
	id, err := mw.identity(r)
	if err != nil {
		mw.fail(w, r, http.StatusUnauthorized, err)
		return nil, false
	}
	u, err := mw.manager.GetUser(id)
	if err != nil {
		status := http.StatusUnauthorized
		if !errors.Is(err, store.ErrUserNotFound) {
			status = http.StatusInternalServerError
		}
		mw.fail(w, r, status, err)
		return nil, false
	}
	return u, true
}

func (mw *Middleware) fail(w http.ResponseWriter, r *http.Request, status int, err error) {
	if mw.OnError != nil {
		mw.OnError(w, r, status, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":  err.Error(),
		"status": status,
	})
}
