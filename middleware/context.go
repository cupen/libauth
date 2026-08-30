package middleware

import (
	"context"

	"github.com/cupen/libauth/model"
)

type contextKey struct{}

// WithUser attaches the authenticated user to a context.
func WithUser(ctx context.Context, u *model.User) context.Context {
	return context.WithValue(ctx, contextKey{}, u)
}

// UserFromContext returns the user previously attached by middleware, or nil.
func UserFromContext(ctx context.Context) *model.User {
	u, _ := ctx.Value(contextKey{}).(*model.User)
	return u
}
