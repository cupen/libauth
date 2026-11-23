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

// NewMiddleware builds HTTP guards for the enforcer. identity must be
// non-nil; get one from HeaderIdentity or write your own.
func NewMiddleware(m *Enforcer, identity IdentityFunc, opts ...middleware.Option) (*Middleware, error) {
	if m == nil {
		// A typed-nil *Enforcer arrives as a non-nil interface.
		return nil, ErrNilAuthorizer
	}
	return middleware.NewMiddleware(m, identity, opts...)
}

func HeaderIdentity(header string) IdentityFunc { return middleware.HeaderIdentity(header) }

func WithOnError(h middleware.ErrorHandler) middleware.Option {
	return middleware.WithOnError(h)
}

func WithUser(ctx context.Context, u *User) context.Context {
	return middleware.WithUser(ctx, u)
}

func UserFromContext(ctx context.Context) *User {
	return middleware.UserFromContext(ctx)
}
