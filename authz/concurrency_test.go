package authz

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cupen/libauth/model"
)

// TestConcurrentAssignRoleNoLostUpdate is the regression test for
// read-modify-write races: goroutines assigning distinct roles to the same
// user must never lose an assignment to each other.
func TestConcurrentAssignRoleNoLostUpdate(t *testing.T) {
	const workers = 8

	e := New()
	if err := e.CreateRole("base", nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateUser("u", "base"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < workers; i++ {
		if err := e.CreateRole(model.RoleID(fmt.Sprintf("r%d", i)), nil, ""); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := e.AssignRole("u", model.RoleID(fmt.Sprintf("r%d", i))); err != nil {
				t.Errorf("AssignRole: %v", err)
			}
		}(i)
	}
	wg.Wait()

	u, err := e.GetUser("u")
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Roles) != workers+1 {
		t.Errorf("lost update: user holds %d roles, want %d (%v)",
			len(u.Roles), workers+1, u.Roles)
	}
}

// TestConcurrentCheckSeesAssign is the regression test for stale cache
// entries surviving a mutation: after AssignRole returns, every subsequent
// Check must observe the grant — even when a warm cache entry for the user
// existed and a concurrent reader raced the mutation.
func TestConcurrentCheckSeesAssign(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		e := New()
		if err := e.CreateRole("editor", []model.Permission{perm("article:write")}, ""); err != nil {
			t.Fatal(err)
		}
		if err := e.CreateRole("viewer", []model.Permission{perm("article:read")}, ""); err != nil {
			t.Fatal(err)
		}
		if err := e.CreateUser("u", "viewer"); err != nil {
			t.Fatal(err)
		}
		// Warm the cache so the mutation's invalidation has something to
		// race with.
		if err := e.Check("u", perm("article:read")); err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = e.Check("u", perm("article:read"))
			}
		}()
		go func() {
			defer wg.Done()
			if err := e.AssignRole("u", "editor"); err != nil {
				t.Errorf("AssignRole: %v", err)
			}
		}()
		wg.Wait()

		// Quiesced: the grant must be visible.
		if err := e.Check("u", perm("article:write")); err != nil {
			t.Fatalf("iter %d: Check after AssignRole returned still denies: %v", iter, err)
		}
	}
}

// TestRoleChangeInvalidatesDescendants is the regression test for subtree
// invalidation: editing a role's permissions or parent must invalidate the
// caches of users holding inheriting roles, not just direct holders.
func TestRoleChangeInvalidatesDescendants(t *testing.T) {
	// dave holds publisher → editor; warm his cache.
	e := newTestEnforcer(t)
	if err := e.Check("dave", perm("article:create")); err != nil {
		t.Fatal(err)
	}

	// GrantPermission on the parent role reaches dave through publisher.
	if err := e.GrantPermission("editor", perm("article:delete")); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("dave", perm("article:delete")); err != nil {
		t.Errorf("descendant holder must see parent role's new permission: %v", err)
	}

	// RevokePermission on the parent must reach him too.
	if err := e.RevokePermission("editor", perm("article:delete")); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("dave", perm("article:delete")); err == nil {
		t.Error("descendant holder must lose the revoked parent permission")
	}

	// Re-pointing an ancestor changes the inherited chain: dave's cache
	// must go even though he does not hold "viewer" directly.
	if err := e.CreateRole("viewer2", []model.Permission{perm("article:purge")}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("dave", perm("article:create")); err != nil {
		t.Fatal(err)
	}
	if err := e.SetParent("editor", "viewer2"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("dave", perm("article:purge")); err != nil {
		t.Errorf("descendant holder must see new ancestor chain: %v", err)
	}

	// Deleting a mid-chain role detaches descendants: their caches must
	// drop the permissions inherited through it.
	if err := e.Check("dave", perm("article:create")); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteRole("editor"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("dave", perm("article:create")); err == nil {
		t.Error("descendant holder must lose permissions inherited through deleted role")
	}
}

// TestCheckWarmPathZeroAllocs pins the hot-path contract: a warm Check is
// a few map lookups and allocates nothing. This is the regression test for
// the deny-payload cost leaking into the allow path.
func TestCheckWarmPathZeroAllocs(t *testing.T) {
	e := newTestEnforcer(t)
	req := perm("article:create")
	if err := e.Check("bob", req); err != nil {
		t.Fatal(err)
	}

	avg := testing.AllocsPerRun(200, func() {
		if err := e.Check("bob", req); err != nil {
			t.Fatal(err)
		}
	})
	if avg != 0 {
		t.Errorf("warm Check allocated %v objects per call, want 0", avg)
	}

	// Warm HasRole and HasPermission likewise stay allocation-free.
	if ok, err := e.HasRole("bob", "editor"); err != nil || !ok {
		t.Fatalf("HasRole: ok=%v err=%v", ok, err)
	}
	if ok, err := e.HasPermission("bob", req); err != nil || !ok {
		t.Fatalf("HasPermission: ok=%v err=%v", ok, err)
	}
	avg = testing.AllocsPerRun(200, func() {
		_, _ = e.HasRole("bob", "editor")
		_, _ = e.HasPermission("bob", req)
	})
	if avg != 0 {
		t.Errorf("warm HasRole/HasPermission allocated %v objects per call, want 0", avg)
	}
}

// TestConcurrentReadersAndWriters hammers every read API against every
// mutation under -race; it asserts no panic and a consistent post-state.
func TestConcurrentReadersAndWriters(t *testing.T) {
	e := newTestEnforcer(t)
	var stop atomic.Bool

	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				_ = e.Check("bob", perm("article:create"))
				_, _ = e.HasRole("bob", "editor")
				_, _ = e.HasPermission("carol", perm("article:read"))
				_, _ = e.PermissionsFor("bob")
				_, _ = e.RolesFor("dave")
				_, _ = e.ListRoles()
				_, _ = e.ListUsers()
			}
		}()
	}

	var writers sync.WaitGroup
	mutations := []func(){
		func() { _ = e.GrantPermission("viewer", perm("x:1")) },
		func() { _ = e.RevokePermission("viewer", perm("x:1")) },
		func() { _ = e.GrantDirectPermission("carol", perm("y:2")) },
		func() { _ = e.RevokeDirectPermission("carol", perm("y:2")) },
		func() { _ = e.AssignRole("carol", "editor") },
		func() { _ = e.RevokeRole("carol", "editor") },
		func() { _ = e.SetParent("publisher", "editor") },
		func() { _ = e.UpdateRole("viewer", []model.Permission{perm("article:read")}, "") },
	}
	for i := 0; i < len(mutations); i++ {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			for j := 0; j < 50; j++ {
				mutations[i]()
			}
		}(i)
	}

	writers.Wait()
	stop.Store(true)
	readers.Wait()

	// Post-state assertions must be order-independent: the contested
	// grants (x:1, y:2, carol's editor role) race by design, so only
	// invariants hold. viewer always keeps article:read (every UpdateRole
	// writes it, Grant/Revoke never touch it).
	if err := e.Check("carol", perm("article:read")); err != nil {
		t.Errorf("post-state: carol read: %v", err)
	}
	// Coherence: whatever the contested state is, the cached view
	// (Check/HasPermission) and the flattened view (PermissionsFor)
	// must agree with each other after quiescence.
	hasChk, err := e.HasPermission("carol", perm("x:1"))
	if err != nil {
		t.Fatalf("HasPermission: %v", err)
	}
	perms, err := e.PermissionsFor("carol")
	if err != nil {
		t.Fatalf("PermissionsFor: %v", err)
	}
	permX := perm("x:1")
	hasInList := false
	for _, p := range perms {
		if p == permX {
			hasInList = true
		}
	}
	if hasChk != hasInList {
		t.Errorf("post-state incoherent: HasPermission(x:1)=%v but PermissionsFor contains it=%v", hasChk, hasInList)
	}
}
