package libauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// contextKey is the private context key type for storing the resolved user.
type contextKey struct{}

// WithUser attaches the authenticated user to a context.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, contextKey{}, u)
}

// UserFromContext returns the user previously attached by middleware, or nil.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(contextKey{}).(*User)
	return u
}

// IdentityFunc extracts the acting user's ID from a request. Returning an
// error means the caller could not be identified (middleware answers 401).
type IdentityFunc func(r *http.Request) (UserID, error)

// HeaderIdentity returns an IdentityFunc reading a header (default
// "X-User-ID"). Intended for demos and internal services; wire your real
// authentication (JWT, session, ...) here in production.
func HeaderIdentity(header string) IdentityFunc {
	if header == "" {
		header = "X-User-ID"
	}
	return func(r *http.Request) (UserID, error) {
		id := r.Header.Get(header)
		if id == "" {
			return "", errors.New("missing identity header " + header)
		}
		return id, nil
	}
}

// Middleware guards http.Handler chains with libauth checks.
type Middleware struct {
	manager  *Manager
	identity IdentityFunc
	// OnError, when set, fully handles error responses. status is the
	// suggested HTTP status code (401, 403 or 500).
	OnError func(w http.ResponseWriter, r *http.Request, status int, err error)
}

// NewMiddleware builds middleware for the manager. A nil identity defaults to
// HeaderIdentity("").
func NewMiddleware(m *Manager, identity IdentityFunc) (*Middleware, error) {
	if m == nil {
		return nil, ErrInvalidIdentityFunc
	}
	if identity == nil {
		identity = HeaderIdentity("")
	}
	return &Middleware{manager: m, identity: identity}, nil
}

// Require returns middleware granting passage only when the identified user
// holds the permission.
func (mw *Middleware) Require(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := mw.authorize(w, r, perm)
			if !ok {
				return
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
}

// RequireAll passes only when the user holds every permission listed.
func (mw *Middleware) RequireAll(perms ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := mw.identify(w, r)
			if !ok {
				return
			}
			for _, p := range perms {
				if _, ok := mw.pass(w, r, u, p); !ok {
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
}

// RequireAny passes when the user holds at least one of the permissions.
func (mw *Middleware) RequireAny(perms ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := mw.identify(w, r)
			if !ok {
				return
			}
			denied := true
			for _, p := range perms {
				granted, err := mw.manager.HasPermission(u.ID, p)
				if err != nil {
					mw.fail(w, r, http.StatusInternalServerError, err)
					return
				}
				if granted {
					denied = false
					break
				}
			}
			if denied {
				required := Permission("<any>")
				if len(perms) == 1 {
					required = perms[0]
				}
				// Also covers the misconfigured empty case: fail closed, never panic.
				mw.fail(w, r, http.StatusForbidden,
					&PermissionDeniedError{UserID: u.ID, User: u, Required: required})
				return
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
}

// RequireRole passes when the user directly holds the role.
func (mw *Middleware) RequireRole(role RoleName) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := mw.identify(w, r)
			if !ok {
				return
			}
			granted, err := mw.manager.HasRole(u.ID, role)
			if err != nil {
				mw.fail(w, r, http.StatusInternalServerError, err)
				return
			}
			if !granted {
				mw.fail(w, r, http.StatusForbidden,
					&PermissionDeniedError{UserID: u.ID, User: u, Required: Permission("role:" + role)})
				return
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
}

func (mw *Middleware) authorize(w http.ResponseWriter, r *http.Request, perm Permission) (*User, bool) {
	u, ok := mw.identify(w, r)
	if !ok {
		return nil, false
	}
	return mw.pass(w, r, u, perm)
}

func (mw *Middleware) pass(w http.ResponseWriter, r *http.Request, u *User, perm Permission) (*User, bool) {
	err := mw.manager.Check(u.ID, perm)
	if err == nil {
		return u, true
	}
	status := http.StatusForbidden
	if errors.Is(err, ErrUserNotFound) {
		status = http.StatusUnauthorized
	}
	mw.fail(w, r, status, err)
	return nil, false
}

func (mw *Middleware) identify(w http.ResponseWriter, r *http.Request) (*User, bool) {
	id, err := mw.identity(r)
	if err != nil {
		mw.fail(w, r, http.StatusUnauthorized, err)
		return nil, false
	}
	u, err := mw.manager.GetUser(id)
	if err != nil {
		status := http.StatusUnauthorized
		if !errors.Is(err, ErrUserNotFound) {
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
