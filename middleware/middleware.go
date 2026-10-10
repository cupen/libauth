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

var (
	// ErrNilAuthorizer rejects middleware construction without an
	// authorizer to consult.
	ErrNilAuthorizer = errors.New("libauth: authorizer is required")
	// ErrNilIdentityFunc rejects middleware construction without an
	// explicit identity source. There is no silent default: wiring the
	// identity (HeaderIdentity, a bearer-token parser, ...) is a decision
	// the caller must make on purpose.
	ErrNilIdentityFunc = errors.New("libauth: identity func is required")
)

// Authorizer is the subset of the permission API the guards depend on.
type Authorizer interface {
	Check(id model.UserID, required model.Permission) error
	HasPermission(id model.UserID, required model.Permission) (bool, error)
	HasRole(id model.UserID, role model.RoleID) (bool, error)
	GetUser(id model.UserID) (*model.User, error)
}

// ErrorHandler fully renders an error response. status is the suggested
// HTTP status code (401, 403 or 500).
type ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, err error)

type Middleware struct {
	manager  Authorizer
	identity IdentityFunc
	onError  ErrorHandler
}

// Option customises a Middleware.
type Option func(*Middleware)

// WithOnError replaces the default JSON error response with a custom
// renderer (e.g. plain-text or an HTML page).
func WithOnError(h ErrorHandler) Option {
	return func(mw *Middleware) { mw.onError = h }
}

// NewMiddleware builds middleware for the authorizer. identity must be
// non-nil — HeaderIdentity("") is the demo identity; production wires a
// real one (see _examples/jwtauth).
func NewMiddleware(m Authorizer, identity IdentityFunc, opts ...Option) (*Middleware, error) {
	if m == nil {
		return nil, ErrNilAuthorizer
	}
	if identity == nil {
		return nil, ErrNilIdentityFunc
	}
	mw := &Middleware{manager: m, identity: identity}
	for _, opt := range opts {
		if opt != nil {
			opt(mw)
		}
	}
	return mw, nil
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
	if u := UserFromContext(r.Context()); u != nil && alreadyResolved(r.Context()) {
		return u, true
	}
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
	if mw.onError != nil {
		mw.onError(w, r, status, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":  err.Error(),
		"status": status,
	})
}
