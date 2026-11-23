// Package libauth implements a multi-role permission system (RBAC).
//
// All public identifiers are re-exported here; the implementation lives in
// model, store, middleware, authz, jwt and branca.
package libauth

import (
	"time"

	"github.com/cupen/libauth/authz"
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

type (
	UserID     = model.UserID
	RoleID     = model.RoleID
	Permission = model.Permission
	User       = model.User
	Role       = model.Role
)

const (
	ActionRead  = model.ActionRead
	ActionWrite = model.ActionWrite
	ActionExec  = model.ActionExec
)

func ParsePermission(s string) (Permission, error) { return model.ParsePermission(s) }

type (
	Store       = store.Store
	MemoryStore = store.MemoryStore
)

var NewMemoryStore = store.NewMemoryStore

type (
	Enforcer = authz.Enforcer
	Option   = authz.Option
)

const (
	DefaultMaxDepth  = authz.DefaultMaxDepth
	DefaultCacheSize = authz.DefaultCacheSize
	// Deprecated: use DefaultCacheSize instead.
	DefaultCacheCapacity = DefaultCacheSize
	DefaultCacheTTL      = authz.DefaultCacheTTL
)

// New creates an Enforcer backed by an in-memory store by default.
func New(opts ...Option) *Enforcer { return authz.New(opts...) }

func WithStore(s Store) Option  { return authz.WithStore(s) }
func WithMaxDepth(n int) Option { return authz.WithMaxDepth(n) }

func WithCacheSize(n int) Option { return authz.WithCacheSize(n) }

// Deprecated: use WithCacheSize instead.
func WithCacheCapacity(n int) Option { return WithCacheSize(n) }

func WithCacheTTL(d time.Duration) Option {
	return authz.WithCacheTTL(d)
}
func WithUnboundedCache() Option { return authz.WithUnboundedCache() }
