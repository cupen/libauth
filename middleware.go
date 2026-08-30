package libauth

import (
	"context"

	"github.com/cupen/libauth/middleware"
)

type (
	Middleware   = middleware.Middleware
	Authorizer   = middleware.Authorizer
	IdentityFunc = middleware.IdentityFunc
)

// NewMiddleware builds middleware for the enforcer. A nil identity defaults
// to HeaderIdentity("").
//
// The explicit nil check here prevents a typed-nil *Enforcer from slipping
// through as a non-nil Authorizer interface value inside the middleware
// subpackage.
func NewMiddleware(m *Enforcer, identity IdentityFunc) (*Middleware, error) {
	if m == nil {
		return nil, ErrInvalidIdentityFunc
	}
	return middleware.NewMiddleware(m, identity)
}

func HeaderIdentity(header string) IdentityFunc { return middleware.HeaderIdentity(header) }

func WithUser(ctx context.Context, u *User) context.Context {
	return middleware.WithUser(ctx, u)
}

func UserFromContext(ctx context.Context) *User {
	return middleware.UserFromContext(ctx)
}
