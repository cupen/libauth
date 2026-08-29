package libauth

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m := New()

	if err := m.CreateRole("admin", []Permission{"*"}); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateRole("editor", []Permission{"article:create", "article:edit", "article:read"}); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateRole("viewer", []Permission{"article:read"}); err != nil {
		t.Fatal(err)
	}
	// publisher inherits everything an editor has, plus publishing.
	if err := m.CreateRole("publisher", []Permission{"article:publish"}, "editor"); err != nil {
		t.Fatal(err)
	}

	users := map[string][]RoleName{
		"alice": {"admin"},
		"bob":   {"editor", "viewer"}, // multi-role
		"carol": {"viewer"},
		"dave":  {"publisher"},
	}
	for id, roles := range users {
		if err := m.CreateUser(id, roles...); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestPermissionMatching(t *testing.T) {
	cases := []struct {
		granted  Permission
		required Permission
		want     bool
	}{
		{"article:create", "article:create", true},
		{"article:create", "article:delete", false},
		{"article:*", "article:delete", true},
		{"article:*", "user:delete", false},
		{"*", "user:delete", true},
		{"*", "anything:at:all", true},
		{"user:*", "user:read", true},
		{"article:read", "article:read:extra", false},
		{"*", "article:read:extra", true}, // global wildcard spans depth
		{"", "article:read", false},
	}
	for _, tc := range cases {
		if got := tc.granted.Matches(tc.required); got != tc.want {
			t.Errorf("Permission(%q).Matches(%q) = %v, want %v", tc.granted, tc.required, got, tc.want)
		}
	}
}

func TestMultiRolePermissionUnion(t *testing.T) {
	m := newTestManager(t)

	// bob holds editor+viewer: union of both permission sets.
	if err := m.Check("bob", "article:create"); err != nil {
		t.Errorf("bob should create articles: %v", err)
	}
	if err := m.Check("bob", "article:read"); err != nil {
		t.Errorf("bob should read articles: %v", err)
	}
	if err := m.Check("bob", "article:delete"); err == nil {
		t.Error("bob should NOT delete articles")
	}

	// carol: viewer only.
	if err := m.Check("carol", "article:read"); err != nil {
		t.Errorf("carol should read articles: %v", err)
	}
	if err := m.Check("carol", "article:create"); err == nil {
		t.Error("carol should NOT create articles")
	}

	// alice: admin wildcard.
	for _, p := range []Permission{"article:delete", "user:create", "anything:at:all"} {
		if err := m.Check("alice", p); err != nil {
			t.Errorf("admin should hold %q: %v", p, err)
		}
	}
}

func TestRoleInheritance(t *testing.T) {
	m := newTestManager(t)

	// dave holds publisher, which inherits editor.
	if err := m.Check("dave", "article:publish"); err != nil {
		t.Errorf("dave should publish: %v", err)
	}
	if err := m.Check("dave", "article:create"); err != nil {
		t.Errorf("dave should create via inherited editor role: %v", err)
	}

	roles, err := m.RolesFor("dave")
	if err != nil {
		t.Fatal(err)
	}
	want := []RoleName{"editor", "publisher"}
	if !reflect.DeepEqual(roles, want) {
		t.Errorf("RolesFor(dave) = %v, want %v", roles, want)
	}
}

func TestDeepInheritanceChain(t *testing.T) {
	m := newTestManager(t)

	// Build a 10-level chain: l1 <- l2 <- ... <- l10.
	if err := m.CreateRole("l1", []Permission{"deep:read"}); err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 10; i++ {
		if err := m.CreateRole(RoleName(fmt.Sprintf("l%d", i)), nil, RoleName(fmt.Sprintf("l%d", i-1))); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.CreateUser("deep-user", "l10"); err != nil {
		t.Fatal(err)
	}
	if err := m.Check("deep-user", "deep:read"); err != nil {
		t.Errorf("permission should resolve through 10 inheritance levels: %v", err)
	}
}

func TestCyclicInheritanceRejected(t *testing.T) {
	m := newTestManager(t)

	if err := m.CreateRole("a", nil, "a"); !errors.Is(err, ErrCyclicInheritance) {
		t.Errorf("self-parent should be cyclic, got %v", err)
	}
	if err := m.CreateRole("a", nil, "admin"); err != nil {
		t.Fatal(err)
	}
	// admin -> a -> admin would be a cycle.
	if err := m.AddParent("admin", "a"); !errors.Is(err, ErrCyclicInheritance) {
		t.Errorf("cycle should be rejected, got %v", err)
	}
}

func TestAssignRevokeRole(t *testing.T) {
	m := newTestManager(t)

	if err := m.AssignRole("carol", "editor"); err != nil {
		t.Fatal(err)
	}
	if err := m.Check("carol", "article:create"); err != nil {
		t.Errorf("carol should create after role grant: %v", err)
	}
	if err := m.RevokeRole("carol", "editor"); err != nil {
		t.Fatal(err)
	}
	if err := m.Check("carol", "article:create"); err == nil {
		t.Error("carol should NOT create after role revocation")
	}

	if err := m.AssignRole("carol", "nope"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("assigning unknown role should fail with ErrRoleNotFound, got %v", err)
	}
}

func TestDirectPermissions(t *testing.T) {
	m := newTestManager(t)

	if err := m.GrantDirectPermission("carol", "article:comment"); err != nil {
		t.Fatal(err)
	}
	if err := m.Check("carol", "article:comment"); err != nil {
		t.Errorf("carol should hold direct permission: %v", err)
	}
	perms, err := m.PermissionsFor("carol")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range perms {
		if p == "article:comment" {
			found = true
		}
	}
	if !found {
		t.Errorf("PermissionsFor should include direct permission, got %v", perms)
	}
	if err := m.RevokeDirectPermission("carol", "article:comment"); err != nil {
		t.Fatal(err)
	}
	if err := m.Check("carol", "article:comment"); err == nil {
		t.Error("direct permission should be revoked")
	}
}

func TestCheckErrors(t *testing.T) {
	m := newTestManager(t)

	err := m.Check("ghost", "article:read")
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown user should yield ErrUserNotFound, got %v", err)
	}

	err = m.Check("carol", "article:delete")
	var denied *PermissionDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected PermissionDeniedError, got %v", err)
	}
	if denied.UserID != "carol" || denied.Required != "article:delete" {
		t.Errorf("unexpected denial details: %+v", denied)
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Error("denial should unwrap to ErrPermissionDenied")
	}
}

func TestUnknownRoleIgnoredInResolution(t *testing.T) {
	m := newTestManager(t)
	// Directly inject a user with a dangling role via the store.
	if err := m.Store().CreateUser(&User{ID: "eve", Roles: []RoleName{"ghost", "viewer"}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Check("eve", "article:read"); err != nil {
		t.Errorf("eve should still read via surviving role: %v", err)
	}
	if err := m.Check("eve", "article:create"); err == nil {
		t.Error("eve should not create")
	}
}

func TestDeleteRoleDetaches(t *testing.T) {
	m := newTestManager(t)

	if err := m.DeleteRole("viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetRole("viewer"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("deleted role should be gone, got %v", err)
	}
	ok, err := m.HasRole("carol", "viewer")
	if err != nil || ok {
		t.Errorf("carol should no longer hold deleted role (ok=%v err=%v)", ok, err)
	}
	if err := m.Check("carol", "article:read"); err == nil {
		t.Error("carol should have lost the permission")
	}
	// dave's publisher must no longer inherit through the deleted role chain.
	if err := m.DeleteRole("editor"); err != nil {
		t.Fatal(err)
	}
	if err := m.Check("dave", "article:create"); err == nil {
		t.Error("dave should have lost inherited editor permissions")
	}
}

func TestUpdateRole(t *testing.T) {
	m := newTestManager(t)

	if err := m.UpdateRole("viewer", []Permission{"article:read", "article:comment"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Check("carol", "article:comment"); err != nil {
		t.Errorf("carol should gain updated permission: %v", err)
	}
}

func TestHasAllAnyPermissions(t *testing.T) {
	m := newTestManager(t)

	ok, err := m.HasAllPermissions("bob", "article:create", "article:read")
	if err != nil || !ok {
		t.Errorf("bob should hold both: ok=%v err=%v", ok, err)
	}
	ok, err = m.HasAllPermissions("bob", "article:create", "article:delete")
	if err != nil || ok {
		t.Errorf("bob lacks delete: ok=%v err=%v", ok, err)
	}
	ok, err = m.HasAnyPermission("carol", "article:create", "article:read")
	if err != nil || !ok {
		t.Errorf("carol holds read: ok=%v err=%v", ok, err)
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	m := newTestManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := RoleName("gen")
			_ = m.CreateUser(UserID(string(rune('a'+i))+"user"), "viewer")
			_ = m.AssignRole(UserID(string(rune('a'+i))+"user"), id)
			_ = m.RevokeRole(UserID(string(rune('a'+i))+"user"), id)
			_, _ = m.PermissionsFor("bob")
			_ = m.GrantPermission("viewer", Permission("gen:rw"+string(rune('a'+i))))
			_ = m.RevokePermission("viewer", Permission("gen:rw"+string(rune('a'+i))))
			_, _ = m.ListUsers()
			_, _ = m.ListRoles()
		}(i)
	}
	wg.Wait()
}

func TestInvalidPermissionsRejected(t *testing.T) {
	m := newTestManager(t)
	if err := m.CreateRole("bad", []Permission{"article:"}); !errors.Is(err, ErrInvalidPermission) {
		t.Errorf("empty segment should be invalid, got %v", err)
	}
	if err := m.GrantPermission("viewer", ":read"); !errors.Is(err, ErrInvalidPermission) {
		t.Errorf("leading colon should be invalid, got %v", err)
	}
	if err := m.CreateRole("ok-role", []Permission{"a:b:c"}); err != nil {
		t.Errorf("multi-segment permission should be valid, got %v", err)
	}
}
