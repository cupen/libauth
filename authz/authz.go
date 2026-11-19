// Package authz is the RBAC orchestration layer: it ties the data model
// (model), the persistence Store and inheritance validation into one API.
package authz

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// DefaultMaxDepth bounds role-inheritance resolution.
const DefaultMaxDepth = 32

// DefaultCacheSize bounds how many per-user permission caches stay in
// memory. Registration alone does not consume cache space; entries are
// created lazily by Check, HasRole, HasPermission and PermissionsFor.
const DefaultCacheSize = 10_000

// DefaultCacheCapacity is the former name of DefaultCacheSize.
// Deprecated: use DefaultCacheSize instead.
const DefaultCacheCapacity = DefaultCacheSize

// DefaultCacheTTL is how long an unused user cache entry stays eligible for
// hits. A zero TTL configured through WithCacheTTL disables time expiry.
const DefaultCacheTTL = 24 * time.Hour

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
// cache invalidation and can leave stale answers behind.
//
// A accessed user gets a memoized cache entry holding its effective permission
// set and direct-role set. Entries are bounded by DefaultCacheSize and
// expire after DefaultCacheTTL without access; role mutations flush the whole
// user cache rather than maintaining per-role reverse indexes.
type Enforcer struct {
	store     store.Store
	maxDepth  int
	cacheSize int
	cacheTTL  time.Duration
	// cacheNow is the cache clock. It is deliberately unexported: production
	// uses time.Now while package tests advance it deterministically.
	cacheNow func() time.Time

	// writeMu serializes mutations so read-modify-write sequences against
	// the store never lose updates to each other.
	writeMu sync.Mutex

	cacheMu sync.RWMutex
	cache   map[model.UserID]*cacheEntry
	// clockRing implements second-chance eviction. Slots may hold stale
	// entries after invalidation; they are recognized and reused when the
	// hand reaches them. It is allocated lazily and unused when unbounded.
	clockRing []*cacheEntry
	clockHand int
	// epoch counts completed mutations. Cache installs record the epoch
	// they were computed under and are dropped when a mutation finished
	// in between, so a stale result can never persist in the cache.
	epoch uint64
}

// cacheEntry is one user's memoized authorization data. Entries are complete
// and immutable once installed: a cold HasRole computes the full entry too,
// which lets warm readers dereference granted and direct under RLock without
// racing a writer filling in the other half. lastAccess and referenced use
// atomics because they are updated on hits under cacheMu.RLock.
type cacheEntry struct {
	uid        model.UserID
	granted    *grantedSet
	direct     map[model.RoleID]struct{}
	lastAccess atomic.Int64 // Unix nanoseconds
	referenced atomic.Bool  // second-chance bit
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

// WithCacheSize bounds the number of lazily populated user cache entries.
// Non-positive values are ignored.
func WithCacheSize(n int) Option {
	return func(e *Enforcer) {
		if n > 0 {
			e.cacheSize = n
		}
	}
}

// WithCacheCapacity is the former name of WithCacheSize.
// Deprecated: use WithCacheSize instead.
func WithCacheCapacity(n int) Option { return WithCacheSize(n) }

// WithCacheTTL sets how long an unused entry remains eligible for hits.
// Zero disables time expiry; negative values are ignored.
func WithCacheTTL(d time.Duration) Option {
	return func(e *Enforcer) {
		if d >= 0 {
			e.cacheTTL = d
		}
	}
}

// WithUnboundedCache restores the pre-bound cache behaviour: entries are
// kept until invalidated and capacity never triggers eviction. TTL settings
// are unaffected.
func WithUnboundedCache() Option {
	return func(e *Enforcer) { e.cacheSize = 0 }
}

func New(opts ...Option) *Enforcer {
	e := &Enforcer{
		store:     store.NewMemoryStore(),
		maxDepth:  DefaultMaxDepth,
		cacheSize: DefaultCacheSize,
		cacheTTL:  DefaultCacheTTL,
		cacheNow:  time.Now,
		cache:     make(map[model.UserID]*cacheEntry),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	if e.cacheNow == nil {
		e.cacheNow = time.Now
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

// invalidateAll drops every user cache entry. Role mutations take this broad
// brush deliberately: they are low-frequency administrative writes, and
// avoiding a per-role reverse index keeps registration memory proportional to
// the Store rather than to the Enforcer.
func (e *Enforcer) invalidateAll() {
	e.commit(e.clearCacheLocked)
}

func (e *Enforcer) clearCacheLocked() {
	clear(e.cache)
	for i := range e.clockRing {
		e.clockRing[i] = nil
	}
	e.clockHand = 0
}

func (e *Enforcer) entryExpiredLocked(entry *cacheEntry, now time.Time) bool {
	if e.cacheTTL <= 0 {
		return false
	}
	last := time.Unix(0, entry.lastAccess.Load())
	return now.Sub(last) > e.cacheTTL
}

func (e *Enforcer) touchEntry(entry *cacheEntry, now time.Time) {
	entry.lastAccess.Store(now.UnixNano())
	entry.referenced.Store(true)
}

// lookupEntry returns a live entry and the epoch sampled around the lookup.
// A hit is touched without acquiring a write lock; atomics keep that safe.
func (e *Enforcer) lookupEntry(uid model.UserID) (*cacheEntry, uint64, bool) {
	now := e.cacheNow()
	e.cacheMu.RLock()
	entry, ok := e.cache[uid]
	epoch := e.epoch
	expired := ok && e.entryExpiredLocked(entry, now)
	e.cacheMu.RUnlock()

	if !ok || expired {
		return nil, epoch, false
	}
	e.touchEntry(entry, now)
	return entry, epoch, true
}

func directRoleSet(u *model.User) map[model.RoleID]struct{} {
	set := make(map[model.RoleID]struct{}, len(u.Roles))
	for _, role := range u.Roles {
		set[role] = struct{}{}
	}
	return set
}

// installEntryLocked stores entry and, when bounded, evicts one victim with
// the second-chance algorithm. Invalidated entries leave stale ring slots;
// those slots are recognized by map identity and reused here in O(1).
func (e *Enforcer) installEntryLocked(entry *cacheEntry, now time.Time) {
	if old := e.cache[entry.uid]; old == entry {
		return
	}
	e.cache[entry.uid] = entry
	if e.cacheSize <= 0 {
		return
	}
	if len(e.clockRing) == 0 {
		e.clockRing = make([]*cacheEntry, e.cacheSize)
	}

	for {
		victim := e.clockRing[e.clockHand]
		if victim == nil || e.cache[victim.uid] != victim || e.entryExpiredLocked(victim, now) {
			e.clockRing[e.clockHand] = entry
			e.clockHand = (e.clockHand + 1) % len(e.clockRing)
			return
		}
		if victim.referenced.CompareAndSwap(true, false) {
			e.clockHand = (e.clockHand + 1) % len(e.clockRing)
			continue
		}
		delete(e.cache, victim.uid)
		e.clockRing[e.clockHand] = entry
		e.clockHand = (e.clockHand + 1) % len(e.clockRing)
		return
	}
}

// loadUserEntry returns the user's complete immutable cache entry. A
// computation racing with a mutation is returned uncached; the next call
// recomputes.
func (e *Enforcer) loadUserEntry(uid model.UserID) (*cacheEntry, error) {
	entry, epoch, ok := e.lookupEntry(uid)
	if ok {
		return entry, nil
	}

	u, err := e.store.GetUser(uid)
	if err != nil {
		return nil, err
	}
	set, err := e.computeGranted(u)
	if err != nil {
		return nil, err
	}
	fresh := &cacheEntry{uid: uid, granted: set, direct: directRoleSet(u)}

	e.cacheMu.Lock()
	if e.epoch == epoch {
		now := e.cacheNow()
		if existing := e.cache[uid]; existing != nil && !e.entryExpiredLocked(existing, now) {
			e.touchEntry(existing, now)
			fresh = existing
		} else {
			fresh.lastAccess.Store(now.UnixNano())
			e.installEntryLocked(fresh, now)
		}
	}
	e.cacheMu.Unlock()
	return fresh, nil
}

// directRolesOf returns the user's directly held roles.
func (e *Enforcer) directRolesOf(uid model.UserID) (map[model.RoleID]struct{}, error) {
	entry, err := e.loadUserEntry(uid)
	if err != nil {
		return nil, err
	}
	return entry.direct, nil
}

// getGrantedSet returns the user's granted-permission set.
func (e *Enforcer) getGrantedSet(uid model.UserID) (*grantedSet, error) {
	entry, err := e.loadUserEntry(uid)
	if err != nil {
		return nil, err
	}
	return entry.granted, nil
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
