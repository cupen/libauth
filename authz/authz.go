// Package authz is the RBAC orchestration layer: it ties the data model
// (model), the persistence Store and inheritance validation into one API.
package authz

import (
	"sync"

	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// DefaultMaxDepth bounds role-inheritance resolution.
const DefaultMaxDepth = 32

// Enforcer is the high-level RBAC API. It is safe for concurrent use.
//
// Concurrency contract:
//   - Reads (Check, Has*, PermissionsFor, RolesFor, Get*, List*) may run in
//     any number of goroutines, with or without concurrent mutations.
//   - Mutations (Create/Update/Delete/Assign/Revoke/Grant/SetParent) are
//     serialized against each other, so concurrent writers never lose
//     updates.
//   - Every answer reflects some point in time between the call's start and
//     its return; once a mutation returns, subsequent reads observe it.
//
// The Enforcer must be the only writer to its Store. External writes bypass
// the cache-coherence bookkeeping and leave stale answers behind.
//
// Each user gets a memoized granted-permission set built from the effective
// role chain plus direct grants; a warm Check is a few map lookups with zero
// allocations. Mutations invalidate the affected entries so the next check
// recomputes lazily.
type Enforcer struct {
	store    store.Store
	maxDepth int

	// writeMu serializes mutations so read-modify-write sequences against
	// the store never lose updates to each other.
	writeMu sync.Mutex

	cacheMu     sync.RWMutex
	cache       map[model.UserID]*grantedSet
	roleHolders map[model.RoleID]map[model.UserID]struct{}
	// directRoles memoizes each user's directly held roles so HasRole
	// answers without touching the store on the hot path.
	directRoles map[model.UserID]map[model.RoleID]struct{}
	// epoch counts completed mutations. Cache installs record the epoch
	// they were computed under and are dropped when a mutation finished
	// in between, so a stale result can never persist in the cache.
	epoch uint64
}

// grantedSet indexes a user's granted permissions by (Resource, Action).
type grantedSet struct {
	byResource map[string]map[string]struct{}
}

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
	if _, ok := g.byResource["*"]; ok {
		return true
	}
	actions, ok := g.byResource[required.Resource]
	if !ok {
		return false
	}
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

// WithStore replaces the backing store (defaults to a MemoryStore). The
// Enforcer must remain the store's only writer.
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

func New(opts ...Option) *Enforcer {
	e := &Enforcer{
		store:       store.NewMemoryStore(),
		maxDepth:    DefaultMaxDepth,
		cache:       make(map[model.UserID]*grantedSet),
		roleHolders: make(map[model.RoleID]map[model.UserID]struct{}),
		directRoles: make(map[model.UserID]map[model.RoleID]struct{}),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// commit finalizes a mutation: it bumps the epoch (dropping any concurrent
// cache install) and applies the given cache bookkeeping. Callers must hold
// writeMu; fn runs under cacheMu.
func (e *Enforcer) commit(fn func()) {
	e.cacheMu.Lock()
	e.epoch++
	fn()
	e.cacheMu.Unlock()
}

func (e *Enforcer) invalidateUser(id model.UserID) {
	e.commit(func() { delete(e.cache, id) })
}

// affectedRoles returns name plus every role that inherits from it,
// directly or transitively. Permission and parent changes on a role alter
// the effective grants of its whole subtree, so their caches must go too.
func (e *Enforcer) affectedRoles(name model.RoleID) map[model.RoleID]struct{} {
	affected := map[model.RoleID]struct{}{name: {}}
	roles, err := e.store.ListRoles()
	if err != nil {
		// Without the role graph, degrade to the conservative minimum.
		return affected
	}
	children := make(map[model.RoleID][]model.RoleID, len(roles))
	for _, r := range roles {
		if r.Parent != "" {
			children[r.Parent] = append(children[r.Parent], r.Name)
		}
	}
	queue := []model.RoleID{name}
	for i := 0; i < len(queue); i++ {
		for _, child := range children[queue[i]] {
			if _, ok := affected[child]; !ok {
				affected[child] = struct{}{}
				queue = append(queue, child)
			}
		}
	}
	return affected
}

// invalidateRole drops the cached granted sets of every user holding name
// or any role descending from it. The reverse index survives — those
// roles and holdings still exist.
func (e *Enforcer) invalidateRole(name model.RoleID) {
	subtree := e.affectedRoles(name)
	e.commit(func() {
		for role := range subtree {
			for uid := range e.roleHolders[role] {
				delete(e.cache, uid)
			}
		}
	})
}

func (e *Enforcer) grantHolder(uid model.UserID, role model.RoleID) {
	e.commit(func() {
		holders, ok := e.roleHolders[role]
		if !ok {
			holders = make(map[model.UserID]struct{})
			e.roleHolders[role] = holders
		}
		holders[uid] = struct{}{}
	})
}

func (e *Enforcer) revokeHolder(uid model.UserID, role model.RoleID) {
	e.commit(func() {
		if holders, ok := e.roleHolders[role]; ok {
			delete(holders, uid)
		}
	})
}

// setDirectRoles replaces the cached direct-role set for uid.
func (e *Enforcer) setDirectRoles(uid model.UserID, roles []model.RoleID) {
	e.commit(func() {
		if len(roles) == 0 {
			delete(e.directRoles, uid)
			return
		}
		set := make(map[model.RoleID]struct{}, len(roles))
		for _, r := range roles {
			set[r] = struct{}{}
		}
		e.directRoles[uid] = set
	})
}

// directRolesOf returns the cached direct-role set for uid, computing it on
// a miss by reading the store. A computation that races with a mutation is
// returned uncached; the next call recomputes.
func (e *Enforcer) directRolesOf(uid model.UserID) (map[model.RoleID]struct{}, error) {
	e.cacheMu.RLock()
	set, ok := e.directRoles[uid]
	epoch := e.epoch
	e.cacheMu.RUnlock()
	if ok {
		return set, nil
	}
	u, err := e.store.GetUser(uid)
	if err != nil {
		return nil, err
	}
	fresh := make(map[model.RoleID]struct{}, len(u.Roles))
	for _, r := range u.Roles {
		fresh[r] = struct{}{}
	}
	e.cacheMu.Lock()
	if e.epoch == epoch {
		if set, ok = e.directRoles[uid]; !ok {
			e.directRoles[uid] = fresh
			set = fresh
		}
	}
	e.cacheMu.Unlock()
	return set, nil
}

// getGrantedSet returns the cached granted set for uid, computing it from
// the store on a miss. A computation that races with a mutation is returned
// uncached; the next call recomputes.
func (e *Enforcer) getGrantedSet(uid model.UserID) (*grantedSet, error) {
	e.cacheMu.RLock()
	set, ok := e.cache[uid]
	epoch := e.epoch
	e.cacheMu.RUnlock()
	if ok {
		return set, nil
	}
	u, err := e.store.GetUser(uid)
	if err != nil {
		return nil, err
	}
	set, err = e.computeGranted(u)
	if err != nil {
		return nil, err
	}
	e.cacheMu.Lock()
	if e.epoch == epoch {
		if existing, ok := e.cache[uid]; ok {
			set = existing
		} else {
			e.cache[uid] = set
			if _, ok := e.directRoles[uid]; !ok {
				fresh := make(map[model.RoleID]struct{}, len(u.Roles))
				for _, r := range u.Roles {
					fresh[r] = struct{}{}
				}
				e.directRoles[uid] = fresh
			}
		}
	}
	e.cacheMu.Unlock()
	return set, nil
}

// computeGranted walks the user's effective roles plus direct grants and
// builds the permission index (without touching the cache).
func (e *Enforcer) computeGranted(u *model.User) (*grantedSet, error) {
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
	return set, nil
}
