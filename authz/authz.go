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

// DefaultCacheSize bounds the number of per-user cache entries.
const DefaultCacheSize = 10_000

// Deprecated: use DefaultCacheSize instead.
const DefaultCacheCapacity = DefaultCacheSize

// DefaultCacheTTL is how long an unused user cache entry stays eligible for
// hits. Zero disables time expiry.
const DefaultCacheTTL = 24 * time.Hour

// Enforcer is the high-level RBAC API. It is safe for concurrent use.
//
// Reads may run concurrently; mutations are serialized and every returned
// mutation is immediately visible to later reads. The Enforcer must be the
// only writer to its Store.
type Enforcer struct {
	store     store.Store
	maxDepth  int
	cacheSize int
	cacheTTL  time.Duration
	cacheNow  func() time.Time // overridable in tests

	writeMu sync.Mutex

	cacheMu   sync.RWMutex
	cache     map[model.UserID]*cacheEntry
	clockRing []*cacheEntry
	clockHand int
	// epoch counts completed mutations; installs from an older epoch are
	// dropped so stale results never persist.
	epoch uint64
}

type cacheEntry struct {
	uid        model.UserID
	granted    *grantedSet
	direct     map[model.RoleID]struct{}
	lastAccess atomic.Int64
	referenced atomic.Bool
}

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

// flatten returns the granted patterns as a slice, not their coverage.
func (g *grantedSet) flatten() []model.Permission {
	out := make([]model.Permission, 0, len(g.byResource)*2)
	for r, actions := range g.byResource {
		for a := range actions {
			out = append(out, model.Perm(r, a))
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

// WithCacheSize bounds the number of lazily populated user cache entries.
// Non-positive values are ignored.
func WithCacheSize(n int) Option {
	return func(e *Enforcer) {
		if n > 0 {
			e.cacheSize = n
		}
	}
}

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

// WithUnboundedCache disables capacity-based eviction.
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

func (e *Enforcer) commit(fn func()) {
	e.cacheMu.Lock()
	e.epoch++
	fn()
	e.cacheMu.Unlock()
}

func (e *Enforcer) invalidateUser(id model.UserID) {
	e.commit(func() { delete(e.cache, id) })
}

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

// installEntryLocked stores entry, evicting a victim with the second-chance
// algorithm when the cache is bounded. Stale ring slots are reused in O(1).
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

// loadUserEntry returns the user's immutable cache entry. A computation that
// races with a mutation is returned uncached and recomputed next time.
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

func (e *Enforcer) directRolesOf(uid model.UserID) (map[model.RoleID]struct{}, error) {
	entry, err := e.loadUserEntry(uid)
	if err != nil {
		return nil, err
	}
	return entry.direct, nil
}

func (e *Enforcer) getGrantedSet(uid model.UserID) (*grantedSet, error) {
	entry, err := e.loadUserEntry(uid)
	if err != nil {
		return nil, err
	}
	return entry.granted, nil
}

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
