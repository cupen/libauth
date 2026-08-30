package middleware

import (
	"net/http"

	"github.com/cupen/libauth/model"
)

// Require grants passage only when the identified user holds the permission.
func (mw *Middleware) Require(perm model.Permission) func(http.Handler) http.Handler {
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

// RequireAll passes only when the user holds every listed permission.
func (mw *Middleware) RequireAll(perms ...model.Permission) func(http.Handler) http.Handler {
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
func (mw *Middleware) RequireAny(perms ...model.Permission) func(http.Handler) http.Handler {
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
				required := model.Permission{Resource: "<any>"}
				if len(perms) == 1 {
					required = perms[0]
				}
				mw.fail(w, r, http.StatusForbidden,
					&model.PermissionDeniedError{UserID: u.ID, User: u, Required: required})
				return
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
}

// RequireRole passes when the user directly holds the role.
func (mw *Middleware) RequireRole(role model.RoleName) func(http.Handler) http.Handler {
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
				required, _ := model.ParsePermission("role:" + string(role))
				mw.fail(w, r, http.StatusForbidden,
					&model.PermissionDeniedError{UserID: u.ID, User: u, Required: required})
				return
			}
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
		})
	}
}
