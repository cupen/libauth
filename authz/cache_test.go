package authz

import (
	"testing"

	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// TestCacheInvalidation exercises every mutation that should bust the cache
// and confirms the next Check sees the new state.
func TestCacheInvalidation(t *testing.T) {
	e := newTestEnforcer(t)

	read := func(p model.Permission) bool { return e.Check("carol", p) == nil }
	articleRead := perm("article:read")
	articleCreate := perm("article:create")
	articleComment := perm("article:comment")

	// Establish cache: carol (viewer) can read but not create.
	if !read(articleRead) {
		t.Fatal("setup: carol should read")
	}
	if read(articleCreate) {
		t.Fatal("setup: carol should NOT create")
	}

	// Promote: AssignRole must invalidate carol.
	if err := e.AssignRole("carol", "editor"); err != nil {
		t.Fatal(err)
	}
	if !read(articleCreate) {
		t.Error("AssignRole should invalidate cache")
	}

	// Demote: RevokeRole must invalidate.
	if err := e.RevokeRole("carol", "editor"); err != nil {
		t.Fatal(err)
	}
	if read(articleCreate) {
		t.Error("RevokeRole should invalidate cache")
	}

	// Direct grant: GrantDirectPermission must invalidate.
	if err := e.GrantDirectPermission("carol", articleComment); err != nil {
		t.Fatal(err)
	}
	if !read(articleComment) {
		t.Error("GrantDirectPermission should invalidate cache")
	}

	if err := e.RevokeDirectPermission("carol", articleComment); err != nil {
		t.Fatal(err)
	}
	if read(articleComment) {
		t.Error("RevokeDirectPermission should invalidate cache")
	}

	// Role mutation: GrantPermission to viewer role must invalidate carol
	// (viewer) and bob (editor+viewer).
	if err := e.GrantPermission("viewer", articleComment); err != nil {
		t.Fatal(err)
	}
	if !read(articleComment) {
		t.Error("GrantPermission should invalidate role holders")
	}

	if err := e.RevokePermission("viewer", articleComment); err != nil {
		t.Fatal(err)
	}
	if read(articleComment) {
		t.Error("RevokePermission should invalidate role holders")
	}

	// UpdateRole mutates the role's permissions wholesale: same expectation.
	if err := e.UpdateRole("viewer", []model.Permission{perm("article:read"), articleComment}); err != nil {
		t.Fatal(err)
	}
	if !read(articleComment) {
		t.Error("UpdateRole should invalidate role holders")
	}

	// AddParent changes the inherited role chain: must invalidate.
	if err := e.AddParent("viewer", "editor"); err != nil {
		t.Fatal(err)
	}
	// carol now inherits editor's permissions through viewer.
	if !read(articleCreate) {
		t.Error("AddParent should invalidate role holders (inherited grant missing)")
	}

	// DeleteRole cascade-detaches and must invalidate holders.
	if err := e.DeleteRole("viewer"); err != nil {
		t.Fatal(err)
	}
	if read(articleRead) {
		t.Error("DeleteRole should cascade-detach and invalidate")
	}
}

// TestCacheIndependentUsers confirms cache entries are scoped per-user.
func TestCacheIndependentUsers(t *testing.T) {
	e := newTestEnforcer(t)

	// Carol (viewer) cache is populated.
	if err := e.Check("carol", perm("article:read")); err != nil {
		t.Fatal(err)
	}

	// Bob's cache must be computed independently — assigning editor to bob
	// must not affect carol's resolved state.
	if err := e.AssignRole("bob", "editor"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("carol", perm("article:create")); err == nil {
		t.Error("carol's cache should be untouched by bob's mutation")
	}

	// Invalidating bob should not invalidate carol.
	e.cacheMu.RLock()
	carolPresent := e.cache["carol"] != nil
	bobPresent := e.cache["bob"] != nil
	e.cacheMu.RUnlock()
	if !carolPresent {
		t.Error("carol's cache should still be populated")
	}
	if bobPresent {
		t.Error("bob's cache should have been invalidated by AssignRole")
	}
}

// TestCacheDeleteUser confirms deleting a user evicts the entry.
func TestCacheDeleteUser(t *testing.T) {
	e := newTestEnforcer(t)
	if err := e.Check("carol", perm("article:read")); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteUser("carol"); err != nil {
		t.Fatal(err)
	}
	e.cacheMu.RLock()
	_, cached := e.cache["carol"]
	e.cacheMu.RUnlock()
	if cached {
		t.Error("DeleteUser should evict cache entry")
	}
	if err := e.Check("carol", perm("article:read")); !errIs(err, store.ErrUserNotFound) {
		t.Errorf("Check after delete: want ErrUserNotFound, got %v", err)
	}
}

func errIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := err.(unwrapper); ok {
			err = u.Unwrap()
			continue
		}
		return false
	}
	return false
}

// BenchmarkCheckHit measures cache-hit cost for a steady-state check.
// Numbers should be orders of magnitude better than BenchmarkCheckCold.
func BenchmarkCheckHit(b *testing.B) {
	e := New()
	if err := e.CreateRole("admin", []model.Permission{{Resource: "*"}}); err != nil {
		b.Fatal(err)
	}
	if err := e.CreateUser("alice", "admin"); err != nil {
		b.Fatal(err)
	}
	req := perm("article:read")
	// Prime cache.
	if err := e.Check("alice", req); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Check("alice", req)
	}
}

// BenchmarkCheckCold measures the cache-miss cost (full recompute).
func BenchmarkCheckCold(b *testing.B) {
	e := New()
	if err := e.CreateRole("admin", []model.Permission{{Resource: "*"}}); err != nil {
		b.Fatal(err)
	}
	if err := e.CreateUser("alice", "admin"); err != nil {
		b.Fatal(err)
	}
	req := perm("article:read")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Force a cache miss by mutating each iteration.
		e.invalidateUser("alice")
		_ = e.Check("alice", req)
	}
}
