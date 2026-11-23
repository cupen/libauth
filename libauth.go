// Package libauth provides authentication and authorization for Go: RBAC
// permissions and net/http middleware, plus JWT, Branca and TOTP in
// subpackages.
//
// The RBAC and middleware APIs are re-exported here; implementations live in
// model, store, middleware and authz.
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

func Perm(resource, action string) Permission { return model.Perm(resource, action) }

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
