package middleware

import (
	"context"

	"github.com/cupen/libauth/model"
)

type (
	contextKey  struct{}
	resolvedKey struct{}
)

// WithUser attaches the authenticated user and marks the request resolved,
// so later guards skip the identity lookup.
func WithUser(ctx context.Context, u *model.User) context.Context {
	ctx = context.WithValue(ctx, contextKey{}, u)
	ctx = context.WithValue(ctx, resolvedKey{}, true)
	return ctx
}

// UserFromContext returns the user previously attached by middleware, or nil.
func UserFromContext(ctx context.Context) *model.User {
	u, _ := ctx.Value(contextKey{}).(*model.User)
	return u
}

func alreadyResolved(ctx context.Context) bool {
	_, ok := ctx.Value(resolvedKey{}).(bool)
	return ok
}
