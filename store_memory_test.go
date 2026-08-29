package libauth

import (
	"errors"
	"testing"
)

func TestMemoryStoreUserLifecycle(t *testing.T) {
	s := NewMemoryStore()

	if err := s.CreateUser(nil); !errors.Is(err, ErrEmptyName) {
		t.Errorf("nil user: got %v", err)
	}
	if err := s.CreateUser(&User{ID: ""}); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty id: got %v", err)
	}
	if err := s.CreateUser(&User{ID: "u1", Roles: []RoleName{"a"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&User{ID: "u1"}); !errors.Is(err, ErrUserExists) {
		t.Errorf("duplicate user: got %v", err)
	}

	// Lookups return copies: mutating them must not corrupt the store.
	u, err := s.GetUser("u1")
	if err != nil {
		t.Fatal(err)
	}
	u.ID = "hacked"
	u.Roles = append(u.Roles, "injected")
	got, err := s.GetUser("u1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "u1" || len(got.Roles) != 1 {
		t.Errorf("store leaked mutable internal state: %+v", got)
	}

	if err := s.DeleteUser("u1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser("u1"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("double delete: got %v", err)
	}
	if _, err := s.GetUser("u1"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("get after delete: got %v", err)
	}
}

func TestMemoryStoreRoleLifecycle(t *testing.T) {
	s := NewMemoryStore()

	if err := s.CreateRole(nil); !errors.Is(err, ErrEmptyName) {
		t.Errorf("nil role: got %v", err)
	}
	if err := s.CreateRole(&Role{Name: ""}); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty name: got %v", err)
	}
	if err := s.CreateRole(&Role{Name: "r1", Permissions: []Permission{"a:b"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRole(&Role{Name: "r1"}); !errors.Is(err, ErrRoleExists) {
		t.Errorf("duplicate role: got %v", err)
	}
	if err := s.UpdateRole(&Role{Name: "ghost"}); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("update unknown role: got %v", err)
	}

	// Lookups return deep copies, including the permission slice.
	r, err := s.GetRole("r1")
	if err != nil {
		t.Fatal(err)
	}
	r.Permissions[0] = "hacked:x"
	r.Permissions = append(r.Permissions, "injected")
	r.Parents = append(r.Parents, "injected-parent")
	again, err := s.GetRole("r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Permissions) != 1 || again.Permissions[0] != "a:b" || len(again.Parents) != 0 {
		t.Errorf("store leaked mutable internal state: %+v", again)
	}

	if err := s.DeleteRole("r1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRole("r1"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("double delete: got %v", err)
	}
	if err := s.UpdateRole(&Role{Name: "r1"}); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("update after delete: got %v", err)
	}
}

func TestMemoryStoreUnknownTargets(t *testing.T) {
	s := NewMemoryStore()

	if err := s.AssignRole("ghost", "r"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("assign to unknown user: got %v", err)
	}
	if err := s.RevokeRole("ghost", "r"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("revoke from unknown user: got %v", err)
	}
	if err := s.GrantUserPermission("ghost", "a:b"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("grant to unknown user: got %v", err)
	}
	if err := s.RevokeUserPermission("ghost", "a:b"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("revoke from unknown user: got %v", err)
	}
	if err := s.GrantPermission("ghost", "a:b"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("grant to unknown role: got %v", err)
	}
	if err := s.RevokePermission("ghost", "a:b"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("revoke from unknown role: got %v", err)
	}
}

func TestMemoryStoreIdempotencyAndSorting(t *testing.T) {
	s := NewMemoryStore()

	// Create out of order to verify sorted listings.
	for _, name := range []RoleName{"b", "a", "c"} {
		if err := s.CreateRole(&Role{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []UserID{"z", "a", "m"} {
		if err := s.CreateUser(&User{ID: id}); err != nil {
			t.Fatal(err)
		}
	}

	// Duplicate grants and assignments are no-ops.
	if err := s.GrantPermission("a", "x:1"); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantPermission("a", "x:1"); err != nil {
		t.Errorf("duplicate grant must be idempotent: %v", err)
	}
	if err := s.AssignRole("a", "b"); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignRole("a", "b"); err != nil {
		t.Errorf("duplicate assignment must be idempotent: %v", err)
	}

	// Revoking something that was never granted is also a no-op.
	if err := s.RevokePermission("a", "nope"); err != nil {
		t.Errorf("revoking ungranted permission: %v", err)
	}
	if err := s.RevokeRole("z", "nope"); err != nil {
		t.Errorf("revoking unassigned role: %v", err)
	}

	roles, err := s.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	var names []RoleName
	for _, r := range roles {
		names = append(names, r.Name)
	}
	if len(names) != 3 || names[0] != "a" || names[1] != "b" || names[2] != "c" {
		t.Errorf("ListRoles should be sorted, got %v", names)
	}

	users, err := s.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 || users[0].ID != "a" || users[2].ID != "z" {
		t.Errorf("ListUsers should be sorted, got ids %v", func() []UserID {
			var ids []UserID
			for _, u := range users {
				ids = append(ids, u.ID)
			}
			return ids
		}())
	}

	r, _ := s.GetRole("a")
	if len(r.Permissions) != 1 {
		t.Errorf("role a should hold exactly one permission, got %v", r.Permissions)
	}
	u, _ := s.GetUser("a")
	if len(u.Roles) != 1 || u.Roles[0] != "b" {
		t.Errorf("user a should hold exactly role b, got %v", u.Roles)
	}
}

func TestMemoryStoreDeleteRoleDetaches(t *testing.T) {
	s := NewMemoryStore()

	if err := s.CreateRole(&Role{Name: "parent"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRole(&Role{Name: "child", Parents: []RoleName{"parent"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&User{ID: "u", Roles: []RoleName{"parent"}}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteRole("parent"); err != nil {
		t.Fatal(err)
	}
	child, _ := s.GetRole("child")
	if len(child.Parents) != 0 {
		t.Errorf("child still references deleted parent: %v", child.Parents)
	}
	u, _ := s.GetUser("u")
	if len(u.Roles) != 0 {
		t.Errorf("user still holds deleted role: %v", u.Roles)
	}
}

func TestMemoryStoreEmptyListings(t *testing.T) {
	s := NewMemoryStore()

	users, err := s.ListUsers()
	if err != nil || len(users) != 0 {
		t.Errorf("empty store should list no users: %v %v", users, err)
	}
	roles, err := s.ListRoles()
	if err != nil || len(roles) != 0 {
		t.Errorf("empty store should list no roles: %v %v", roles, err)
	}
}
