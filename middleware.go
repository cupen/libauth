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

// NewMiddleware builds middleware for the enforcer. identity must be
// non-nil — HeaderIdentity("") is the demo identity; production wires a
// real one.
func NewMiddleware(m *Enforcer, identity IdentityFunc, opts ...middleware.Option) (*Middleware, error) {
	if m == nil {
		// A typed-nil *Enforcer reaches the interface parameter as
		// non-nil; catch it here.
		return nil, ErrNilAuthorizer
	}
	return middleware.NewMiddleware(m, identity, opts...)
}

func HeaderIdentity(header string) IdentityFunc { return middleware.HeaderIdentity(header) }

// WithOnError replaces the middleware's default JSON error response.
func WithOnError(h middleware.ErrorHandler) middleware.Option {
	return middleware.WithOnError(h)
}

func WithUser(ctx context.Context, u *User) context.Context {
	return middleware.WithUser(ctx, u)
}

func UserFromContext(ctx context.Context) *User {
	return middleware.UserFromContext(ctx)
}
