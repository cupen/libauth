package authz

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

func TestCacheOptionDefaultsAndOverrides(t *testing.T) {
	if DefaultCacheSize != 10_000 || DefaultCacheCapacity != DefaultCacheSize {
		t.Fatalf("default cache size = %d, legacy alias = %d, want 10000", DefaultCacheSize, DefaultCacheCapacity)
	}
	e := New()
	if e.cacheSize != DefaultCacheSize {
		t.Fatalf("default capacity = %d, want %d", e.cacheSize, DefaultCacheSize)
	}
	if e.cacheTTL != DefaultCacheTTL {
		t.Fatalf("default TTL = %s, want %s", e.cacheTTL, DefaultCacheTTL)
	}

	e = New(WithCacheSize(2), WithCacheTTL(time.Minute))
	if e.cacheSize != 2 || e.cacheTTL != time.Minute {
		t.Fatalf("explicit options: capacity=%d ttl=%s", e.cacheSize, e.cacheTTL)
	}

	e = New(WithCacheSize(-1), WithCacheTTL(-time.Second))
	if e.cacheSize != DefaultCacheSize || e.cacheTTL != DefaultCacheTTL {
		t.Fatalf("invalid options changed defaults: capacity=%d ttl=%s", e.cacheSize, e.cacheTTL)
	}

	e = New(WithCacheSize(2), WithUnboundedCache())
	if e.cacheSize != 0 {
		t.Fatalf("WithUnboundedCache: capacity=%d, want 0", e.cacheSize)
	}

	e = New(WithCacheTTL(0))
	if e.cacheTTL != 0 {
		t.Fatalf("WithCacheTTL(0): ttl=%s, want disabled", e.cacheTTL)
	}

	e = New(WithCacheCapacity(3))
	if e.cacheSize != 3 {
		t.Fatalf("legacy WithCacheCapacity: size=%d, want 3", e.cacheSize)
	}
	e = New(WithCacheCapacity(-1))
	if e.cacheSize != DefaultCacheSize {
		t.Fatalf("legacy invalid capacity changed default size to %d", e.cacheSize)
	}
}

func TestCreateUserDoesNotPopulateCache(t *testing.T) {
	e := New(WithCacheTTL(0))
	if err := e.CreateRole("viewer", []model.Permission{perm("article:read")}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateUser("alice", "viewer"); err != nil {
		t.Fatal(err)
	}
	if got := len(e.cache); got != 0 {
		t.Fatalf("CreateUser populated cache with %d entries, want 0", got)
	}

	if ok, err := e.HasRole("alice", "viewer"); err != nil || !ok {
		t.Fatalf("HasRole: ok=%v err=%v", ok, err)
	}
	if got := len(e.cache); got != 1 {
		t.Fatalf("HasRole cache entries = %d, want 1", got)
	}
}

func TestCacheSizeSecondChance(t *testing.T) {
	e := New(WithCacheSize(2), WithCacheTTL(0))
	if err := e.CreateRole("viewer", []model.Permission{perm("article:read")}, ""); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"u1", "u2", "u3"} {
		if err := e.CreateUser(id, "viewer"); err != nil {
			t.Fatal(err)
		}
	}

	for _, id := range []string{"u1", "u2", "u1"} {
		if err := e.Check(id, perm("article:read")); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Check("u3", perm("article:read")); err != nil {
		t.Fatal(err)
	}

	if got := len(e.cache); got != 2 {
		t.Fatalf("cache entries = %d, want capacity 2", got)
	}
	if _, ok := e.cache["u1"]; !ok {
		t.Fatal("recently used u1 was evicted before cold u2")
	}
	if _, ok := e.cache["u2"]; ok {
		t.Fatal("cold u2 survived eviction")
	}
	if _, ok := e.cache["u3"]; !ok {
		t.Fatal("u3 was not cached")
	}

	// Eviction changes performance only, never authorization answers.
	if err := e.Check("u2", perm("article:read")); err != nil {
		t.Fatalf("Check after eviction: %v", err)
	}
}

func TestCacheTTLExpires(t *testing.T) {
	s := &countingStore{Store: store.NewMemoryStore()}
	now := time.Unix(1_700_000_000, 0)
	e := New(WithStore(s), WithCacheTTL(time.Minute))
	e.cacheNow = func() time.Time { return now }

	if err := e.CreateRole("viewer", []model.Permission{perm("article:read")}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateUser("alice", "viewer"); err != nil {
		t.Fatal(err)
	}

	if err := e.Check("alice", perm("article:read")); err != nil {
		t.Fatal(err)
	}
	s.getUserCalls = 0
	for i := 0; i < 3; i++ {
		if err := e.Check("alice", perm("article:read")); err != nil {
			t.Fatal(err)
		}
	}
	if s.getUserCalls != 0 {
		t.Fatalf("warm TTL hits read Store %d times, want 0", s.getUserCalls)
	}

	now = now.Add(2 * time.Minute)
	if err := e.Check("alice", perm("article:read")); err != nil {
		t.Fatal(err)
	}
	if s.getUserCalls != 1 {
		t.Fatalf("expired entry read Store %d times, want 1", s.getUserCalls)
	}
}

func TestCacheEntrySharedByDirectAndGranted(t *testing.T) {
	e := New(WithCacheTTL(0))
	if err := e.CreateRole("viewer", []model.Permission{perm("article:read")}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateUser("alice", "viewer"); err != nil {
		t.Fatal(err)
	}

	if ok, err := e.HasRole("alice", "viewer"); err != nil || !ok {
		t.Fatalf("HasRole: ok=%v err=%v", ok, err)
	}
	e.cacheMu.RLock()
	entry := e.cache["alice"]
	e.cacheMu.RUnlock()
	if entry == nil || entry.direct == nil || entry.granted == nil {
		t.Fatalf("after HasRole: entry=%+v, want complete direct and granted halves", entry)
	}

	if err := e.Check("alice", perm("article:read")); err != nil {
		t.Fatal(err)
	}
	e.cacheMu.RLock()
	after := e.cache["alice"]
	e.cacheMu.RUnlock()
	if after != entry {
		t.Fatalf("Check created a separate entry: before=%p after=%p", entry, after)
	}
}

func TestRoleMutationFlushesUserCache(t *testing.T) {
	e := newTestEnforcer(t)
	for _, id := range []string{"bob", "carol", "dave"} {
		if err := e.Check(id, perm("article:read")); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.cache) != 3 {
		t.Fatalf("setup cache entries = %d, want 3", len(e.cache))
	}

	if err := e.GrantPermission("viewer", perm("article:comment")); err != nil {
		t.Fatal(err)
	}
	if len(e.cache) != 0 {
		t.Fatalf("role mutation left %d cache entries, want flush", len(e.cache))
	}
	if err := e.Check("carol", perm("article:comment")); err != nil {
		t.Fatalf("carol should see new role permission: %v", err)
	}
}

func TestPreloadedStoreRoleRevocationInvalidates(t *testing.T) {
	s := store.NewMemoryStore()
	read := perm("article:read")
	if err := s.CreateRole(&model.Role{Name: "viewer", Permissions: []model.Permission{read}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&model.User{ID: "alice", Roles: []model.RoleID{"viewer"}}); err != nil {
		t.Fatal(err)
	}

	e := New(WithStore(s), WithCacheTTL(0))
	if err := e.Check("alice", read); err != nil {
		t.Fatal(err)
	}
	if err := e.RevokePermission("viewer", read); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("alice", read); !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("Check after revoke = %v, want permission denied", err)
	}
}

func TestDeleteRoleInvalidatesDeepDescendant(t *testing.T) {
	e := New(WithCacheTTL(0))
	if err := e.CreateRole("a", []model.Permission{perm("root:read")}, ""); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"z", "y", "x"} {
		var parent string
		switch name {
		case "z":
			parent = "a"
		case "y":
			parent = "z"
		case "x":
			parent = "y"
		}
		if err := e.CreateRole(name, nil, parent); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.CreateUser("u", "x"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("u", perm("root:read")); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteRole("a"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("u", perm("root:read")); !errors.Is(err, model.ErrPermissionDenied) {
		t.Fatalf("deep descendant still inherits deleted role: %v", err)
	}
}

func TestHasRoleColdCacheRacingMutationReturnsFresh(t *testing.T) {
	base := store.NewMemoryStore()
	if err := base.CreateRole(&model.Role{Name: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := base.CreateRole(&model.Role{Name: "unrelated"}); err != nil {
		t.Fatal(err)
	}
	if err := base.CreateUser(&model.User{ID: "u", Roles: []model.RoleID{"admin"}}); err != nil {
		t.Fatal(err)
	}

	s := &gatedStore{
		Store:   base,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	e := New(WithStore(s), WithCacheTTL(0))

	result := make(chan bool, 1)
	go func() {
		ok, err := e.HasRole("u", "admin")
		result <- err == nil && ok
	}()
	<-s.entered
	if err := e.GrantPermission("unrelated", perm("x:y")); err != nil {
		t.Fatal(err)
	}
	close(s.release)
	if ok := <-result; !ok {
		t.Fatal("unrelated concurrent mutation made HasRole lose a directly held role")
	}
}

func TestDefaultCacheSizeBoundsManyUsers(t *testing.T) {
	e := New(WithCacheTTL(0))
	if err := e.CreateRole("viewer", []model.Permission{perm("article:read")}, ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= DefaultCacheSize; i++ {
		if err := e.CreateUser(model.UserID("u"+strconv.Itoa(i)), "viewer"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i <= DefaultCacheSize; i++ {
		if err := e.Check(model.UserID("u"+strconv.Itoa(i)), perm("article:read")); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(e.cache); got > DefaultCacheSize {
		t.Fatalf("cache entries = %d, want <= %d", got, DefaultCacheSize)
	}
}

type countingStore struct {
	store.Store
	getUserCalls int
}

func (s *countingStore) GetUser(id model.UserID) (*model.User, error) {
	s.getUserCalls++
	return s.Store.GetUser(id)
}

type gatedStore struct {
	store.Store
	entered chan struct{}
	release chan struct{}
}

func (s *gatedStore) GetUser(id model.UserID) (*model.User, error) {
	if id == "u" {
		close(s.entered)
		<-s.release
	}
	return s.Store.GetUser(id)
}

func BenchmarkCheckWithEviction(b *testing.B) {
	const users = 16
	e := New(WithCacheSize(users-1), WithCacheTTL(0))
	if err := e.CreateRole("viewer", []model.Permission{perm("article:read")}, ""); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < users; i++ {
		if err := e.CreateUser(model.UserID("u"+strconv.Itoa(i)), "viewer"); err != nil {
			b.Fatal(err)
		}
	}
	req := perm("article:read")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := e.Check(model.UserID("u"+strconv.Itoa(i%users)), req); err != nil {
			b.Fatal(err)
		}
	}
}
