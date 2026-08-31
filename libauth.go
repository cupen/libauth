// Package libauth implements a multi-role permission system (RBAC).
//
// A user is granted a permission when ANY of its roles (including roles
// inherited transitively through parent roles) matches the permission, or
// when the user holds the permission directly.
//
// The implementation is layered: core data types in model, the persistence
// contract in store, the HTTP guards in middleware and the RBAC
// orchestration in authz (as the Enforcer type). All public identifiers are
// re-exported from this package so callers only need one import.
//
// Stateless identity tokens come in two flavours: signed JWTs in the jwt
// subpackage (HS256 / Ed25519, stdlib only) and encrypted branca tokens in
// the branca subpackage (XChaCha20-Poly1305, golang.org/x/crypto). Both
// expose Encode / Decode; the middleware takes a plain net/http
// IdentityFunc that performs whatever token verification the deployment
// needs (typically extracting the bearer token and reading its sub claim).
package libauth

import (
	"github.com/cupen/libauth/authz"
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// Core RBAC data types, re-exported from the model subpackage.
type (
	UserID     = model.UserID
	RoleName   = model.RoleName
	Permission = model.Permission
	User       = model.User
	Role       = model.Role
)

// ParsePermission parses a "resource:action" string into a Permission.
func ParsePermission(s string) (Permission, error) { return model.ParsePermission(s) }

// Store is the persistence contract; MemoryStore is its in-memory reference
// implementation.
type (
	Store       = store.Store
	MemoryStore = store.MemoryStore
)

var NewMemoryStore = store.NewMemoryStore

// Enforcer is the high-level RBAC API.
type (
	Enforcer = authz.Enforcer
	Option   = authz.Option
)

const DefaultMaxDepth = authz.DefaultMaxDepth

// New creates an Enforcer backed by an in-memory store by default.
func New(opts ...Option) *Enforcer { return authz.New(opts...) }

func WithStore(s Store) Option  { return authz.WithStore(s) }
func WithMaxDepth(n int) Option { return authz.WithMaxDepth(n) }
