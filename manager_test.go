package libauth

import (
	"errors"
	"fmt"
	"testing"
)

func TestWithStoreOption(t *testing.T) {
	shared := NewMemoryStore()
	if err := shared.CreateUser(&User{ID: "pre"}); err != nil {
		t.Fatal(err)
	}

	m := New(WithStore(shared))
	if _, err := m.GetUser("pre"); err != nil {
		t.Errorf("manager should see pre-existing users in the injected store: %v", err)
	}
	if m.Store() != shared {
		t.Error("Store() should return the injected store")
	}
	if New().Store() == nil {
		t.Error("default manager must always have a store")
	}
}

func TestWithMaxDepth(t *testing.T) {
	m := New(WithMaxDepth(3))

	// Chain: l1 <- l2 <- l3 <- l4 <- l5.
	if err := m.CreateRole("l1", []Permission{"deep:read"}); err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 5; i++ {
		if err := m.CreateRole(RoleName(fmt.Sprintf("l%d", i)), nil, RoleName(fmt.Sprintf("l%d", i-1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.CreateUser("deep", "l5"); err != nil {
		t.Fatal(err)
	}

	if _, err := m.RolesFor("deep"); !errors.Is(err, ErrInheritanceDepth) {
		t.Errorf("5-level chain with maxDepth=3: want ErrInheritanceDepth, got %v", err)
	}
	if err := m.Check("deep", "deep:read"); !errors.Is(err, ErrInheritanceDepth) {
		t.Errorf("Check should propagate ErrInheritanceDepth, got %v", err)
	}

	// Non-positive depths are ignored; the default applies.
	loose := New(WithMaxDepth(0), WithMaxDepth(-5))
	if loose.maxDepth != DefaultMaxDepth {
		t.Errorf("invalid WithMaxDepth values should be ignored, got %d", loose.maxDepth)
	}
	mustRole(t, loose, "a", []Permission{"x:1"})
	mustRole(t, loose, "b", nil, "a")
	mustRole(t, loose, "c", nil, "b")
	if err := loose.CreateUser("u", "c"); err != nil {
		t.Fatal(err)
	}
	if err := loose.Check("u", "x:1"); err != nil {
		t.Errorf("3-level chain under the default depth should resolve: %v", err)
	}
}

// mustRole creates a role with optional parents.
func mustRole(t *testing.T, m *Manager, name RoleName, perms []Permission, parents ...RoleName) {
	t.Helper()
	if err := m.CreateRole(name, perms, parents...); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyAndDuplicateNames(t *testing.T) {
	m := New()

	if err := m.CreateUser(""); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty user id: got %v", err)
	}
	if err := m.CreateUser("dup"); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateUser("dup"); !errors.Is(err, ErrUserExists) {
		t.Errorf("duplicate user: got %v", err)
	}

	if err := m.CreateRole("", nil); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty role name: got %v", err)
	}
	if err := m.UpdateRole("", nil); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty role name on update: got %v", err)
	}
	if err := m.CreateRole("dup-role", nil); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateRole("dup-role", nil); !errors.Is(err, ErrRoleExists) {
		t.Errorf("duplicate role: got %v", err)
	}
}

func TestCreateRoleWithUnknownParent(t *testing.T) {
	m := New()
	if err := m.CreateRole("orphan", nil, "ghost"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("unknown parent should be rejected: got %v", err)
	}
}

func TestAddParent(t *testing.T) {
	m := New()
	if err := m.CreateRole("a", nil); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateRole("b", nil); err != nil {
		t.Fatal(err)
	}

	if err := m.AddParent("a", "b"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddParent("a", "b"); err != nil {
		t.Error("re-adding an existing parent must be a no-op")
	}
	if r, _ := m.GetRole("a"); len(r.Parents) != 1 {
		t.Errorf("a should have exactly one parent, got %v", r.Parents)
	}

	if err := m.AddParent("ghost", "a"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("unknown role: got %v", err)
	}
	if err := m.AddParent("a", "ghost"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("unknown parent: got %v", err)
	}

	// a already inherits from b; making b inherit from a closes a cycle.
	if err := m.AddParent("b", "a"); !errors.Is(err, ErrCyclicInheritance) {
		t.Errorf("cycle must be rejected: got %v", err)
	}
}

func TestUpdateRoleCycleRejection(t *testing.T) {
	m := New()
	if err := m.CreateRole("a", nil); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateRole("b", nil); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateRole("a", nil, "b"); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateRole("b", nil, "a"); !errors.Is(err, ErrCyclicInheritance) {
		t.Errorf("cycle must be rejected: got %v", err)
	}
	// The rejected update must not have been applied.
	if b, _ := m.GetRole("b"); len(b.Parents) != 0 {
		t.Errorf("rejected update leaked into the store: %v", b.Parents)
	}
	if err := m.UpdateRole("ghost", nil); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("unknown role: got %v", err)
	}
}

func TestGrantValidation(t *testing.T) {
	m := New()
	if err := m.CreateRole("r", nil); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateUser("u"); err != nil {
		t.Fatal(err)
	}

	if err := m.GrantPermission("r", "a:"); !errors.Is(err, ErrInvalidPermission) {
		t.Errorf("malformed role permission: got %v", err)
	}
	if err := m.GrantPermission("ghost", "a:b"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("unknown role: got %v", err)
	}
	if err := m.GrantDirectPermission("ghost", "a:b"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown user: got %v", err)
	}
	if err := m.GrantDirectPermission("u", "a:"); !errors.Is(err, ErrInvalidPermission) {
		t.Errorf("malformed direct permission: got %v", err)
	}
}

func TestLookupUnknownUsers(t *testing.T) {
	m := newTestManager(t)

	if _, err := m.RolesFor("ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("RolesFor: got %v", err)
	}
	if _, err := m.PermissionsFor("ghost"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("PermissionsFor: got %v", err)
	}
	if _, err := m.HasPermission("ghost", "article:read"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("HasPermission: got %v", err)
	}
	if err := m.Check("ghost", "article:read"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Check: got %v", err)
	}
}

func TestDeleteUser(t *testing.T) {
	m := newTestManager(t)
	if err := m.CreateUser("temp", "viewer"); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteUser("temp"); err != nil {
		t.Fatal(err)
	}

	if err := m.Check("temp", "article:read"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("Check after delete: got %v", err)
	}
	if _, err := m.HasPermission("temp", "article:read"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("HasPermission after delete: got %v", err)
	}
	if err := m.DeleteUser("temp"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("double delete: got %v", err)
	}
}

func TestHasRoleVariants(t *testing.T) {
	m := newTestManager(t)

	// dave holds publisher, which inherits editor — HasRole is direct-only.
	if ok, _ := m.HasRole("dave", "editor"); ok {
		t.Error("HasRole must not follow inheritance (use RolesFor for the chain)")
	}
	if ok, err := m.HasRole("dave", "publisher"); err != nil || !ok {
		t.Errorf("dave holds publisher: ok=%v err=%v", ok, err)
	}
	if ok, _ := m.HasRole("bob", "nonexistent"); ok {
		t.Error("unknown role must not match")
	}

	if ok, err := m.HasAnyRole("carol", "admin", "viewer"); err != nil || !ok {
		t.Errorf("carol holds viewer: ok=%v err=%v", ok, err)
	}
	if ok, _ := m.HasAnyRole("carol", "admin"); ok {
		t.Error("carol holds no admin role")
	}
	if ok, err := m.HasAllRoles("bob", "editor", "viewer"); err != nil || !ok {
		t.Errorf("bob holds both roles: ok=%v err=%v", ok, err)
	}
	if ok, _ := m.HasAllRoles("bob", "editor", "admin"); ok {
		t.Error("bob lacks admin")
	}

	// Vacuous calls: all-of-nothing passes, any-of-nothing fails.
	if ok, err := m.HasAllRoles("bob"); err != nil || !ok {
		t.Errorf("HasAllRoles with no roles must pass: ok=%v err=%v", ok, err)
	}
	if ok, _ := m.HasAnyRole("bob"); ok {
		t.Error("HasAnyRole with no roles must fail")
	}

	// Unknown users error out consistently.
	if _, err := m.HasRole("ghost", "viewer"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("HasRole: got %v", err)
	}
	if _, err := m.HasAnyRole("ghost", "viewer"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("HasAnyRole: got %v", err)
	}
	if _, err := m.HasAllRoles("ghost", "viewer"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("HasAllRoles: got %v", err)
	}
}

func TestAllPermissionsAndAnyPermissionsEmpty(t *testing.T) {
	m := newTestManager(t)

	// Vacuous semantics mirror HasAllRoles/HasAnyRole.
	if ok, err := m.HasAllPermissions("bob"); err != nil || !ok {
		t.Errorf("HasAllPermissions with no permissions must pass: ok=%v err=%v", ok, err)
	}
	if ok, _ := m.HasAnyPermission("bob"); ok {
		t.Error("HasAnyPermission with no permissions must fail")
	}
}
