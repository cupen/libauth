package authz

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// perm parses a "resource:action" string for tests.
func perm(s string) model.Permission {
	p, err := model.ParsePermission(s)
	if err != nil {
		panic(err)
	}
	return p
}

func newTestEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e := New()

	if err := e.CreateRole("admin", []model.Permission{perm("*")}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateRole("editor", []model.Permission{perm("article:create"), perm("article:edit"), perm("article:read")}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateRole("viewer", []model.Permission{perm("article:read")}, ""); err != nil {
		t.Fatal(err)
	}
	// publisher inherits everything an editor has, plus publishing.
	if err := e.CreateRole("publisher", []model.Permission{perm("article:publish")}, "editor"); err != nil {
		t.Fatal(err)
	}

	users := map[string][]model.RoleName{
		"alice": {"admin"},
		"bob":   {"editor", "viewer"}, // multi-role
		"carol": {"viewer"},
		"dave":  {"publisher"},
	}
	for id, roles := range users {
		if err := e.CreateUser(id, roles...); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func TestPermissionMatching(t *testing.T) {
	cases := []struct {
		granted  model.Permission
		required model.Permission
		want     bool
	}{
		{perm("article:create"), perm("article:create"), true},
		{perm("article:create"), perm("article:delete"), false},
		{perm("article:*"), perm("article:delete"), true},
		{perm("article:*"), perm("user:delete"), false},
		{perm("*"), perm("user:delete"), true},
		{perm("*"), perm("anything:at:all"), true},
		{perm("user:*"), perm("user:read"), true},
		{perm("article:read"), perm("article:read:extra"), false},
		{perm("*"), perm("article:read:extra"), true}, // global wildcard spans depth
		{model.Permission{}, perm("article:read"), false},
	}
	for _, tc := range cases {
		if got := tc.granted.Matches(tc.required); got != tc.want {
			t.Errorf("%+v.Matches(%+v) = %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}

func TestMultiRolePermissionUnion(t *testing.T) {
	e := newTestEnforcer(t)

	// bob holds editor+viewer: union of both permission sets.
	if err := e.Check("bob", perm("article:create")); err != nil {
		t.Errorf("bob should create articles: %v", err)
	}
	if err := e.Check("bob", perm("article:read")); err != nil {
		t.Errorf("bob should read articles: %v", err)
	}
	if err := e.Check("bob", perm("article:delete")); err == nil {
		t.Error("bob should NOT delete articles")
	}

	// carol: viewer only.
	if err := e.Check("carol", perm("article:read")); err != nil {
		t.Errorf("carol should read articles: %v", err)
	}
	if err := e.Check("carol", perm("article:create")); err == nil {
		t.Error("carol should NOT create articles")
	}

	// alice: admin wildcard.
	for _, p := range []model.Permission{perm("article:delete"), perm("user:create"), perm("anything:at:all")} {
		if err := e.Check("alice", p); err != nil {
			t.Errorf("admin should hold %+v: %v", p, err)
		}
	}
}

func TestRoleInheritance(t *testing.T) {
	e := newTestEnforcer(t)

	// dave holds publisher, which inherits editor.
	if err := e.Check("dave", perm("article:publish")); err != nil {
		t.Errorf("dave should publish: %v", err)
	}
	if err := e.Check("dave", perm("article:create")); err != nil {
		t.Errorf("dave should create via inherited editor role: %v", err)
	}

	roles, err := e.RolesFor("dave")
	if err != nil {
		t.Fatal(err)
	}
	want := []model.RoleName{"editor", "publisher"}
	if !reflect.DeepEqual(roles, want) {
		t.Errorf("RolesFor(dave) = %v, want %v", roles, want)
	}
}

func TestDeepInheritanceChain(t *testing.T) {
	e := newTestEnforcer(t)

	// Build a 10-level chain: l1 <- l2 <- ... <- l10.
	if err := e.CreateRole("l1", []model.Permission{perm("deep:read")}, ""); err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 10; i++ {
		if err := e.CreateRole(model.RoleName(fmt.Sprintf("l%d", i)), nil, model.RoleName(fmt.Sprintf("l%d", i-1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.CreateUser("deep-user", "l10"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("deep-user", perm("deep:read")); err != nil {
		t.Errorf("permission should resolve through 10 inheritance levels: %v", err)
	}
}

func TestCyclicInheritanceRejected(t *testing.T) {
	e := newTestEnforcer(t)

	if err := e.CreateRole("a", nil, "a"); !errors.Is(err, ErrCyclicInheritance) {
		t.Errorf("self-parent should be cyclic, got %v", err)
	}
	if err := e.CreateRole("a", nil, "admin"); err != nil {
		t.Fatal(err)
	}
	// admin -> a -> admin would be a cycle.
	if err := e.SetParent("admin", "a"); !errors.Is(err, ErrCyclicInheritance) {
		t.Errorf("cycle should be rejected, got %v", err)
	}
}

func TestAssignRevokeRole(t *testing.T) {
	e := newTestEnforcer(t)

	if err := e.AssignRole("carol", "editor"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("carol", perm("article:create")); err != nil {
		t.Errorf("carol should create after role grant: %v", err)
	}
	if err := e.RevokeRole("carol", "editor"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("carol", perm("article:create")); err == nil {
		t.Error("carol should NOT create after role revocation")
	}

	if err := e.AssignRole("carol", "nope"); !errors.Is(err, store.ErrRoleNotFound) {
		t.Errorf("assigning unknown role should fail with ErrRoleNotFound, got %v", err)
	}
}

func TestDirectPermissions(t *testing.T) {
	e := newTestEnforcer(t)

	if err := e.GrantDirectPermission("carol", perm("article:comment")); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("carol", perm("article:comment")); err != nil {
		t.Errorf("carol should hold direct permission: %v", err)
	}
	perms, err := e.PermissionsFor("carol")
	if err != nil {
		t.Fatal(err)
	}
	want := perm("article:comment")
	found := false
	for _, p := range perms {
		if p == want {
			found = true
		}
	}
	if !found {
		t.Errorf("PermissionsFor should include direct permission, got %v", perms)
	}
	if err := e.RevokeDirectPermission("carol", perm("article:comment")); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("carol", perm("article:comment")); err == nil {
		t.Error("direct permission should be revoked")
	}
}

func TestCheckErrors(t *testing.T) {
	e := newTestEnforcer(t)

	err := e.Check("ghost", perm("article:read"))
	if !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("unknown user should yield ErrUserNotFound, got %v", err)
	}

	err = e.Check("carol", perm("article:delete"))
	var denied *model.PermissionDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected PermissionDeniedError, got %v", err)
	}
	if denied.UserID != "carol" || denied.Required != perm("article:delete") {
		t.Errorf("unexpected denial details: %+v", denied)
	}
	if !errors.Is(err, model.ErrPermissionDenied) {
		t.Error("denial should unwrap to ErrPermissionDenied")
	}
}

func TestUnknownRoleIgnoredInResolution(t *testing.T) {
	e := newTestEnforcer(t)
	// Directly inject a user with a dangling role via the store.
	if err := e.Store().CreateUser(&model.User{ID: "eve", Roles: []model.RoleName{"ghost", "viewer"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("eve", perm("article:read")); err != nil {
		t.Errorf("eve should still read via surviving role: %v", err)
	}
	if err := e.Check("eve", perm("article:create")); err == nil {
		t.Error("eve should not create")
	}
}

func TestDeleteRoleDetaches(t *testing.T) {
	e := newTestEnforcer(t)

	if err := e.DeleteRole("viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.GetRole("viewer"); !errors.Is(err, store.ErrRoleNotFound) {
		t.Errorf("deleted role should be gone, got %v", err)
	}
	ok, err := e.HasRole("carol", "viewer")
	if err != nil || ok {
		t.Errorf("carol should no longer hold deleted role (ok=%v err=%v)", ok, err)
	}
	if err := e.Check("carol", perm("article:read")); err == nil {
		t.Error("carol should have lost the permission")
	}
	// dave's publisher must no longer inherit through the deleted role chain.
	if err := e.DeleteRole("editor"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("dave", perm("article:create")); err == nil {
		t.Error("dave should have lost inherited editor permissions")
	}
}

func TestUpdateRole(t *testing.T) {
	e := newTestEnforcer(t)

	if err := e.UpdateRole("viewer", []model.Permission{perm("article:read"), perm("article:comment")}, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("carol", perm("article:comment")); err != nil {
		t.Errorf("carol should gain updated permission: %v", err)
	}
}

func TestHasAllAnyPermissions(t *testing.T) {
	e := newTestEnforcer(t)

	ok, err := e.HasAllPermissions("bob", perm("article:create"), perm("article:read"))
	if err != nil || !ok {
		t.Errorf("bob should hold both: ok=%v err=%v", ok, err)
	}
	ok, err = e.HasAllPermissions("bob", perm("article:create"), perm("article:delete"))
	if err != nil || ok {
		t.Errorf("bob lacks delete: ok=%v err=%v", ok, err)
	}
	ok, err = e.HasAnyPermission("carol", perm("article:create"), perm("article:read"))
	if err != nil || !ok {
		t.Errorf("carol holds read: ok=%v err=%v", ok, err)
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	e := newTestEnforcer(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := model.RoleName("gen")
			_ = e.CreateUser(model.UserID(string(rune('a'+i))+"user"), "viewer")
			_ = e.AssignRole(model.UserID(string(rune('a'+i))+"user"), id)
			_ = e.RevokeRole(model.UserID(string(rune('a'+i))+"user"), id)
			_, _ = e.PermissionsFor("bob")
			_ = e.GrantPermission("viewer", model.Permission{Resource: "gen", Action: "rw" + string(rune('a'+i))})
			_ = e.RevokePermission("viewer", model.Permission{Resource: "gen", Action: "rw" + string(rune('a'+i))})
			_, _ = e.ListUsers()
			_, _ = e.ListRoles()
		}(i)
	}
	wg.Wait()
}

func TestInvalidPermissionsRejected(t *testing.T) {
	e := newTestEnforcer(t)
	bad := model.Permission{Resource: "article", Action: ""}
	if err := e.CreateRole("bad", []model.Permission{bad}, ""); !errors.Is(err, model.ErrInvalidPermission) {
		t.Errorf("empty action should be invalid, got %v", err)
	}
	if err := e.GrantPermission("viewer", bad); !errors.Is(err, model.ErrInvalidPermission) {
		t.Errorf("empty action grant should be invalid, got %v", err)
	}
	if err := e.CreateRole("ok-role", []model.Permission{perm("a:b:c")}, ""); err != nil {
		t.Errorf("multi-segment permission should be valid, got %v", err)
	}
}

func TestWithStoreOption(t *testing.T) {
	shared := store.NewMemoryStore()
	if err := shared.CreateUser(&model.User{ID: "pre"}); err != nil {
		t.Fatal(err)
	}

	e := New(WithStore(shared))
	if _, err := e.GetUser("pre"); err != nil {
		t.Errorf("enforcer should see pre-existing users in the injected store: %v", err)
	}
	if e.Store() != shared {
		t.Error("Store() should return the injected store")
	}
	if New().Store() == nil {
		t.Error("default enforcer must always have a store")
	}
}

func TestWithMaxDepth(t *testing.T) {
	// Write-time enforcement: chains deeper than maxDepth are rejected when
	// the role that would over-deepen them is created.
	e := New(WithMaxDepth(3))

	// Chain: l1 <- l2 <- l3 <- l4 (3 edges) is fine; l5 would need 4.
	if err := e.CreateRole("l1", []model.Permission{perm("deep:read")}, ""); err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 4; i++ {
		if err := e.CreateRole(model.RoleName(fmt.Sprintf("l%d", i)), nil, model.RoleName(fmt.Sprintf("l%d", i-1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.CreateRole("l5", nil, "l4"); !errors.Is(err, ErrInheritanceDepth) {
		t.Errorf("4-edge chain with maxDepth=3: want ErrInheritanceDepth, got %v", err)
	}
	if err := e.CreateUser("deep", "l4"); err != nil {
		t.Fatal(err)
	}
	if err := e.Check("deep", perm("deep:read")); err != nil {
		t.Errorf("chain within the cap should resolve: %v", err)
	}

	// Non-positive depths are ignored; the default applies.
	loose := New(WithMaxDepth(0), WithMaxDepth(-5))
	if loose.maxDepth != DefaultMaxDepth {
		t.Errorf("invalid WithMaxDepth values should be ignored, got %d", loose.maxDepth)
	}
	mustRole(t, loose, "a", []model.Permission{perm("x:1")}, "")
	mustRole(t, loose, "b", nil, "a")
	mustRole(t, loose, "c", nil, "b")
	if err := loose.CreateUser("u", "c"); err != nil {
		t.Fatal(err)
	}
	if err := loose.Check("u", perm("x:1")); err != nil {
		t.Errorf("3-level chain under the default depth should resolve: %v", err)
	}
}

// mustRole creates a role with a parent ("" for none).
func mustRole(t *testing.T, e *Enforcer, name model.RoleName, perms []model.Permission, parent model.RoleName) {
	t.Helper()
	if err := e.CreateRole(name, perms, parent); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyAndDuplicateNames(t *testing.T) {
	e := New()

	if err := e.CreateUser(""); !errors.Is(err, store.ErrEmptyName) {
		t.Errorf("empty user id: got %v", err)
	}
	if err := e.CreateUser("dup"); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateUser("dup"); !errors.Is(err, store.ErrUserExists) {
		t.Errorf("duplicate user: got %v", err)
	}

	if err := e.CreateRole("", nil, ""); !errors.Is(err, store.ErrEmptyName) {
		t.Errorf("empty role name: got %v", err)
	}
	if err := e.UpdateRole("", nil, ""); !errors.Is(err, store.ErrEmptyName) {
		t.Errorf("empty role name on update: got %v", err)
	}
	if err := e.CreateRole("dup-role", nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateRole("dup-role", nil, ""); !errors.Is(err, store.ErrRoleExists) {
		t.Errorf("duplicate role: got %v", err)
	}
}

func TestCreateRoleWithUnknownParent(t *testing.T) {
	e := New()
	if err := e.CreateRole("orphan", nil, "ghost"); !errors.Is(err, store.ErrRoleNotFound) {
		t.Errorf("unknown parent should be rejected: got %v", err)
	}
}

func TestSetParent(t *testing.T) {
	e := New()
	if err := e.CreateRole("a", nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateRole("b", nil, ""); err != nil {
		t.Fatal(err)
	}

	if err := e.SetParent("a", "b"); err != nil {
		t.Fatal(err)
	}
	if err := e.SetParent("a", "b"); err != nil {
		t.Error("re-setting the same parent must be a no-op")
	}
	if r, _ := e.GetRole("a"); r.Parent != "b" {
		t.Errorf("a's parent should be b, got %q", r.Parent)
	}

	// An empty parent detaches the role from its inheritance chain.
	if err := e.SetParent("a", ""); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.GetRole("a"); r.Parent != "" {
		t.Errorf("a should have no parent, got %q", r.Parent)
	}
	if err := e.SetParent("a", "b"); err != nil {
		t.Fatal(err)
	}

	if err := e.SetParent("ghost", "a"); !errors.Is(err, store.ErrRoleNotFound) {
		t.Errorf("unknown role: got %v", err)
	}
	if err := e.SetParent("a", "ghost"); !errors.Is(err, store.ErrRoleNotFound) {
		t.Errorf("unknown parent: got %v", err)
	}

	// a already inherits from b; making b inherit from a closes a cycle.
	if err := e.SetParent("b", "a"); !errors.Is(err, ErrCyclicInheritance) {
		t.Errorf("cycle must be rejected: got %v", err)
	}
}

func TestUpdateRoleCycleRejection(t *testing.T) {
	e := New()
	if err := e.CreateRole("a", nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateRole("b", nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.UpdateRole("a", nil, "b"); err != nil {
		t.Fatal(err)
	}
	if err := e.UpdateRole("b", nil, "a"); !errors.Is(err, ErrCyclicInheritance) {
		t.Errorf("cycle must be rejected: got %v", err)
	}
	// The rejected update must not have been applied.
	if b, _ := e.GetRole("b"); b.Parent != "" {
		t.Errorf("rejected update leaked into the store: %q", b.Parent)
	}
	if err := e.UpdateRole("ghost", nil, ""); !errors.Is(err, store.ErrRoleNotFound) {
		t.Errorf("unknown role: got %v", err)
	}
}

func TestGrantValidation(t *testing.T) {
	e := New()
	if err := e.CreateRole("r", nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateUser("u"); err != nil {
		t.Fatal(err)
	}

	bad := model.Permission{Resource: "a", Action: ""}
	if err := e.GrantPermission("r", bad); !errors.Is(err, model.ErrInvalidPermission) {
		t.Errorf("malformed role permission: got %v", err)
	}
	if err := e.GrantPermission("ghost", perm("a:b")); !errors.Is(err, store.ErrRoleNotFound) {
		t.Errorf("unknown role: got %v", err)
	}
	if err := e.GrantDirectPermission("ghost", perm("a:b")); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("unknown user: got %v", err)
	}
	if err := e.GrantDirectPermission("u", bad); !errors.Is(err, model.ErrInvalidPermission) {
		t.Errorf("malformed direct permission: got %v", err)
	}
}

func TestLookupUnknownUsers(t *testing.T) {
	e := newTestEnforcer(t)

	if _, err := e.RolesFor("ghost"); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("RolesFor: got %v", err)
	}
	if _, err := e.PermissionsFor("ghost"); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("PermissionsFor: got %v", err)
	}
	if _, err := e.HasPermission("ghost", perm("article:read")); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("HasPermission: got %v", err)
	}
	if err := e.Check("ghost", perm("article:read")); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("Check: got %v", err)
	}
}

func TestDeleteUser(t *testing.T) {
	e := newTestEnforcer(t)
	if err := e.CreateUser("temp", "viewer"); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteUser("temp"); err != nil {
		t.Fatal(err)
	}

	if err := e.Check("temp", perm("article:read")); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("Check after delete: got %v", err)
	}
	if _, err := e.HasPermission("temp", perm("article:read")); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("HasPermission after delete: got %v", err)
	}
	if err := e.DeleteUser("temp"); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("double delete: got %v", err)
	}
}

func TestHasRoleVariants(t *testing.T) {
	e := newTestEnforcer(t)

	// dave holds publisher, which inherits editor — HasRole is direct-only.
	if ok, _ := e.HasRole("dave", "editor"); ok {
		t.Error("HasRole must not follow inheritance (use RolesFor for the chain)")
	}
	if ok, err := e.HasRole("dave", "publisher"); err != nil || !ok {
		t.Errorf("dave holds publisher: ok=%v err=%v", ok, err)
	}
	if ok, _ := e.HasRole("bob", "nonexistent"); ok {
		t.Error("unknown role must not match")
	}

	if ok, err := e.HasAnyRole("carol", "admin", "viewer"); err != nil || !ok {
		t.Errorf("carol holds viewer: ok=%v err=%v", ok, err)
	}
	if ok, err := e.HasAnyRole("carol", "admin"); err != nil || ok {
		t.Errorf("carol holds no admin role: ok=%v err=%v", ok, err)
	}
	if ok, err := e.HasAllRoles("bob", "editor", "viewer"); err != nil || !ok {
		t.Errorf("bob holds both roles: ok=%v err=%v", ok, err)
	}
	if ok, _ := e.HasAllRoles("bob", "editor", "admin"); ok {
		t.Error("bob lacks admin")
	}

	// Vacuous calls: all-of-nothing passes, any-of-nothing fails.
	if ok, err := e.HasAllRoles("bob"); err != nil || !ok {
		t.Errorf("HasAllRoles with no roles must pass: ok=%v err=%v", ok, err)
	}
	if ok, _ := e.HasAnyRole("bob"); ok {
		t.Error("HasAnyRole with no roles must fail")
	}

	// Unknown users error out consistently.
	if _, err := e.HasRole("ghost", "viewer"); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("HasRole: got %v", err)
	}
	if _, err := e.HasAnyRole("ghost", "viewer"); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("HasAnyRole: got %v", err)
	}
	if _, err := e.HasAllRoles("ghost", "viewer"); !errors.Is(err, store.ErrUserNotFound) {
		t.Errorf("HasAllRoles: got %v", err)
	}
}

func TestAllPermissionsAndAnyPermissionsEmpty(t *testing.T) {
	e := newTestEnforcer(t)

	// Vacuous semantics mirror HasAllRoles/HasAnyRole.
	if ok, err := e.HasAllPermissions("bob"); err != nil || !ok {
		t.Errorf("HasAllPermissions with no permissions must pass: ok=%v err=%v", ok, err)
	}
	if ok, _ := e.HasAnyPermission("bob"); ok {
		t.Error("HasAnyPermission with no permissions must fail")
	}
}
