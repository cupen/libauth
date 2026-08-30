// Package authz provides the Enforcer, the orchestration layer that ties the
// RBAC data model (model subpackage), the persistence Store (store
// subpackage) and inheritance validation into a single API.
package authz

import (
	"sync"

	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// DefaultMaxDepth bounds role-inheritance resolution.
const DefaultMaxDepth = 32

// Enforcer is the high-level RBAC API.
//
// Each user gets a memoized granted-permission set (cache) computed from
// their effective role chain and direct grants; permission checks hit the
// cache in O(1) (a few map lookups, no iteration). Mutations invalidate
// the affected entries (and the role→holders reverse index) so the next
// check recomputes lazily.
type Enforcer struct {
	store    store.Store
	maxDepth int

	cacheMu     sync.RWMutex
	cache       map[model.UserID]*grantedSet
	roleHolders map[model.RoleName]map[model.UserID]struct{}
}

// grantedSet indexes a user's granted permissions by (Resource, Action) for
// O(1) pattern-aware lookup. A resource entry with the action "*" grants
// every action under that resource; a resource entry of "*" grants every
// resource and action.
type grantedSet struct {
	byResource map[string]map[string]struct{}
}

// add records one granted permission into the index.
func (g *grantedSet) add(p model.Permission) {
	actions, ok := g.byResource[p.Resource]
	if !ok {
		actions = make(map[string]struct{})
		g.byResource[p.Resource] = actions
	}
	actions[p.Action] = struct{}{}
}

// has reports whether the granted set covers required.
func (g *grantedSet) has(required model.Permission) bool {
	if g == nil {
		return false
	}
	// Global wildcard: {Resource:"*"}.
	if actions, ok := g.byResource["*"]; ok {
		_ = actions // presence is enough; "*" covers everything.
		return true
	}
	actions, ok := g.byResource[required.Resource]
	if !ok {
		return false
	}
	// Per-resource wildcard: {Resource: r, Action:"*"}.
	if _, ok := actions["*"]; ok {
		return true
	}
	_, ok = actions[required.Action]
	return ok
}

// flatten returns the granted permissions as a sorted slice (literal
// patterns, not their expanded coverage).
func (g *grantedSet) flatten() []model.Permission {
	out := make([]model.Permission, 0, len(g.byResource)*2)
	for r, actions := range g.byResource {
		for a := range actions {
			out = append(out, model.Permission{Resource: r, Action: a})
		}
	}
	return out
}

// Option configures an Enforcer.
type Option func(*Enforcer)

// WithStore replaces the backing store (defaults to a MemoryStore).
func WithStore(s store.Store) Option {
	return func(e *Enforcer) { e.store = s }
}

// WithMaxDepth overrides the maximum role-inheritance depth.
func WithMaxDepth(n int) Option {
	return func(e *Enforcer) {
		if n > 0 {
			e.maxDepth = n
		}
	}
}

// New creates an Enforcer backed by an in-memory store by default.
func New(opts ...Option) *Enforcer {
	e := &Enforcer{
		store:       store.NewMemoryStore(),
		maxDepth:    DefaultMaxDepth,
		cache:       make(map[model.UserID]*grantedSet),
		roleHolders: make(map[model.RoleName]map[model.UserID]struct{}),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Store exposes the backing store.
func (e *Enforcer) Store() store.Store { return e.store }

// invalidateUser drops the cached granted-set for one user (next check
// recomputes).
func (e *Enforcer) invalidateUser(id model.UserID) {
	e.cacheMu.Lock()
	delete(e.cache, id)
	e.cacheMu.Unlock()
}

// invalidateRoleHolders drops the cached granted-set for every user that
// holds the given role (directly or through inheritance).
func (e *Enforcer) invalidateRoleHolders(role model.RoleName) {
	e.cacheMu.Lock()
	for uid := range e.roleHolders[role] {
		delete(e.cache, uid)
	}
	e.cacheMu.Unlock()
}

// grantHolder records that uid holds role (used to keep roleHolders in sync
// for fast invalidation).
func (e *Enforcer) grantHolder(uid model.UserID, role model.RoleName) {
	e.cacheMu.Lock()
	holders, ok := e.roleHolders[role]
	if !ok {
		holders = make(map[model.UserID]struct{})
		e.roleHolders[role] = holders
	}
	holders[uid] = struct{}{}
	e.cacheMu.Unlock()
}

// revokeHolder removes uid from role's holders set.
func (e *Enforcer) revokeHolder(uid model.UserID, role model.RoleName) {
	e.cacheMu.Lock()
	if holders, ok := e.roleHolders[role]; ok {
		delete(holders, uid)
	}
	e.cacheMu.Unlock()
}

// getGrantedSet returns the cached granted set for uid, computing it on
// miss. The fast path reads only the cache (no store touch on hit).
func (e *Enforcer) getGrantedSet(uid model.UserID) (*grantedSet, error) {
	e.cacheMu.RLock()
	set, ok := e.cache[uid]
	e.cacheMu.RUnlock()
	if ok {
		return set, nil
	}

	u, err := e.store.GetUser(uid)
	if err != nil {
		return nil, err
	}
	return e.computeAndCache(u)
}

// computeAndCache walks the user's effective roles + direct grants and stores
// the result. Caller is expected to have just had a miss.
func (e *Enforcer) computeAndCache(u *model.User) (*grantedSet, error) {
	roles, err := e.resolveRoles(u)
	if err != nil {
		return nil, err
	}
	set := &grantedSet{byResource: make(map[string]map[string]struct{}, 16)}
	for _, name := range roles {
		role, err := e.store.GetRole(name)
		if err != nil {
			if err == store.ErrRoleNotFound {
				continue
			}
			return nil, err
		}
		for _, p := range role.Permissions {
			set.add(p)
		}
	}
	for _, p := range u.Direct {
		set.add(p)
	}

	e.cacheMu.Lock()
	if existing, ok := e.cache[u.ID]; ok {
		set = existing
	} else {
		e.cache[u.ID] = set
	}
	e.cacheMu.Unlock()
	return set, nil
}
