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
// Each user gets a memoized granted-permission set built from the
// effective role chain plus direct grants; Check hits the cache in O(1).
// Mutations invalidate the affected entries (and the role→holders reverse
// index) so the next check recomputes lazily.
type Enforcer struct {
	store    store.Store
	maxDepth int

	cacheMu     sync.RWMutex
	cache       map[model.UserID]*grantedSet
	roleHolders map[model.RoleID]map[model.UserID]struct{}
	// directRoles memoizes each user's directly held roles so HasRole
	// answers without touching the store on the hot path.
	directRoles map[model.UserID]map[model.RoleID]struct{}
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

func (e *Enforcer) Store() store.Store { return e.store }

func (e *Enforcer) invalidateUser(id model.UserID) {
	e.cacheMu.Lock()
	delete(e.cache, id)
	e.cacheMu.Unlock()
}

func (e *Enforcer) invalidateRoleHolders(role model.RoleID) {
	e.cacheMu.Lock()
	for uid := range e.roleHolders[role] {
		delete(e.cache, uid)
	}
	e.cacheMu.Unlock()
}

func (e *Enforcer) grantHolder(uid model.UserID, role model.RoleID) {
	e.cacheMu.Lock()
	holders, ok := e.roleHolders[role]
	if !ok {
		holders = make(map[model.UserID]struct{})
		e.roleHolders[role] = holders
	}
	holders[uid] = struct{}{}
	e.cacheMu.Unlock()
}

func (e *Enforcer) revokeHolder(uid model.UserID, role model.RoleID) {
	e.cacheMu.Lock()
	if holders, ok := e.roleHolders[role]; ok {
		delete(holders, uid)
	}
	e.cacheMu.Unlock()
}

// setDirectRoles replaces the cached direct-role set for uid.
func (e *Enforcer) setDirectRoles(uid model.UserID, roles []model.RoleID) {
	e.cacheMu.Lock()
	if len(roles) == 0 {
		delete(e.directRoles, uid)
	} else {
		set := make(map[model.RoleID]struct{}, len(roles))
		for _, r := range roles {
			set[r] = struct{}{}
		}
		e.directRoles[uid] = set
	}
	e.cacheMu.Unlock()
}

// directRolesOf returns the cached direct-role set for uid, computing it on
// miss by reading the store.
func (e *Enforcer) directRolesOf(uid model.UserID) (map[model.RoleID]struct{}, error) {
	e.cacheMu.RLock()
	set, ok := e.directRoles[uid]
	e.cacheMu.RUnlock()
	if ok {
		return set, nil
	}
	u, err := e.store.GetUser(uid)
	if err != nil {
		return nil, err
	}
	e.cacheMu.Lock()
	if set, ok = e.directRoles[uid]; !ok {
		fresh := make(map[model.RoleID]struct{}, len(u.Roles))
		for _, r := range u.Roles {
			fresh[r] = struct{}{}
		}
		e.directRoles[uid] = fresh
		set = fresh
	}
	e.cacheMu.Unlock()
	return set, nil
}

// getGrantedSet returns the cached granted set for uid.
func (e *Enforcer) getGrantedSet(uid model.UserID) (*grantedSet, error) {
	set, _, _, err := e.getGrantedSetFull(uid)
	return set, err
}

// getGrantedSetFull returns the granted set along with the user and the
// resolved role chain used to derive it. Check on the denial path uses the
// user and roles to populate *PermissionDeniedError without a second store
// round-trip.
func (e *Enforcer) getGrantedSetFull(uid model.UserID) (*grantedSet, *model.User, []model.RoleID, error) {
	e.cacheMu.RLock()
	set, ok := e.cache[uid]
	e.cacheMu.RUnlock()
	if ok {
		u, err := e.store.GetUser(uid)
		if err != nil {
			return nil, nil, nil, err
		}
		roles, err := e.resolveRoles(u)
		if err != nil {
			return set, u, u.Roles, nil
		}
		return set, u, roles, nil
	}

	u, err := e.store.GetUser(uid)
	if err != nil {
		return nil, nil, nil, err
	}
	set, roles, err := e.computeAndCache(u)
	return set, u, roles, err
}

// computeAndCache walks the user's effective roles + direct grants and
// stores the result. Caller is expected to have just had a miss.
func (e *Enforcer) computeAndCache(u *model.User) (*grantedSet, []model.RoleID, error) {
	roles, err := e.resolveRoles(u)
	if err != nil {
		return nil, nil, err
	}
	set := &grantedSet{byResource: make(map[string]map[string]struct{}, 16)}
	for _, name := range roles {
		role, err := e.store.GetRole(name)
		if err != nil {
			if err == store.ErrRoleNotFound {
				continue
			}
			return nil, nil, err
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
	if _, ok := e.directRoles[u.ID]; !ok {
		fresh := make(map[model.RoleID]struct{}, len(u.Roles))
		for _, r := range u.Roles {
			fresh[r] = struct{}{}
		}
		e.directRoles[u.ID] = fresh
	}
	e.cacheMu.Unlock()
	return set, roles, nil
}