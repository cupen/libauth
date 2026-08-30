package store

import (
	"errors"
	"testing"

	"github.com/cupen/libauth/model"
)

func TestMemoryStoreUserCRUD(t *testing.T) {
	s := NewMemoryStore()

	if err := s.CreateUser(nil); !errors.Is(err, ErrEmptyName) {
		t.Errorf("nil user: got %v", err)
	}
	if err := s.CreateUser(&model.User{ID: ""}); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty id: got %v", err)
	}
	if err := s.UpdateUser(&model.User{ID: "ghost"}); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("update unknown user: got %v", err)
	}
	if err := s.UpdateUser(nil); !errors.Is(err, ErrEmptyName) {
		t.Errorf("update nil user: got %v", err)
	}

	if err := s.CreateUser(&model.User{ID: "u1", Roles: []model.RoleName{"a"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&model.User{ID: "u1"}); !errors.Is(err, ErrUserExists) {
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

	// UpdateUser replaces the persisted record.
	if err := s.UpdateUser(&model.User{ID: "u1", Roles: []model.RoleName{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	again, err := s.GetUser("u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Roles) != 2 || again.Roles[1] != "b" {
		t.Errorf("UpdateUser did not persist: %+v", again)
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

func TestMemoryStoreRoleCRUD(t *testing.T) {
	s := NewMemoryStore()

	if err := s.CreateRole(nil); !errors.Is(err, ErrEmptyName) {
		t.Errorf("nil role: got %v", err)
	}
	if err := s.CreateRole(&model.Role{Name: ""}); !errors.Is(err, ErrEmptyName) {
		t.Errorf("empty name: got %v", err)
	}
	if err := s.UpdateRole(&model.Role{Name: "ghost"}); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("update unknown role: got %v", err)
	}
	if err := s.UpdateRole(nil); !errors.Is(err, ErrEmptyName) {
		t.Errorf("update nil role: got %v", err)
	}

	if err := s.CreateRole(&model.Role{Name: "r1", Permissions: []model.Permission{{Resource: "a", Action: "b"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRole(&model.Role{Name: "r1"}); !errors.Is(err, ErrRoleExists) {
		t.Errorf("duplicate role: got %v", err)
	}

	// Lookups return deep copies, including the permission slice.
	r, err := s.GetRole("r1")
	if err != nil {
		t.Fatal(err)
	}
	r.Permissions[0] = model.Permission{Resource: "hacked", Action: "x"}
	r.Permissions = append(r.Permissions, model.Permission{Resource: "injected"})
	r.Parent = "injected-parent"
	again, err := s.GetRole("r1")
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Permissions) != 1 || again.Permissions[0] != (model.Permission{Resource: "a", Action: "b"}) || again.Parent != "" {
		t.Errorf("store leaked mutable internal state: %+v", again)
	}

	// UpdateRole replaces the persisted record.
	if err := s.UpdateRole(&model.Role{Name: "r1", Parent: "p"}); err != nil {
		t.Fatal(err)
	}
	r3, _ := s.GetRole("r1")
	if len(r3.Permissions) != 0 || r3.Parent != "p" {
		t.Errorf("UpdateRole did not persist: %+v", r3)
	}

	if err := s.DeleteRole("r1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRole("r1"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("double delete: got %v", err)
	}
	if err := s.UpdateRole(&model.Role{Name: "r1"}); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("update after delete: got %v", err)
	}
}

func TestMemoryStoreDeleteRoleIsShallow(t *testing.T) {
	// Stores do not cascade-detach — that is the caller's responsibility
	// (authz.Enforcer.DeleteRole). Verify the store leaves dangling refs
	// alone so callers can choose their own cascade policy.
	s := NewMemoryStore()
	if err := s.CreateRole(&model.Role{Name: "parent"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRole(&model.Role{Name: "child", Parent: "parent"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(&model.User{ID: "u", Roles: []model.RoleName{"parent"}}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteRole("parent"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRole("parent"); !errors.Is(err, ErrRoleNotFound) {
		t.Errorf("parent should be gone: %v", err)
	}
	// Caller is expected to clean these up.
	child, _ := s.GetRole("child")
	if child.Parent != "parent" {
		t.Errorf("store unexpectedly mutated dangling refs: %+v", child)
	}
	u, _ := s.GetUser("u")
	if len(u.Roles) != 1 || u.Roles[0] != "parent" {
		t.Errorf("store unexpectedly mutated dangling refs: %+v", u)
	}
}

func TestMemoryStoreListSortedAndEmpty(t *testing.T) {
	s := NewMemoryStore()

	for _, name := range []model.RoleName{"b", "a", "c"} {
		if err := s.CreateRole(&model.Role{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []model.UserID{"z", "a", "m"} {
		if err := s.CreateUser(&model.User{ID: id}); err != nil {
			t.Fatal(err)
		}
	}

	roles, err := s.ListRoles()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]model.RoleName, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	if len(names) != 3 || names[0] != "a" || names[1] != "b" || names[2] != "c" {
		t.Errorf("ListRoles should be sorted, got %v", names)
	}

	users, err := s.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 || users[0].ID != "a" || users[2].ID != "z" {
		t.Errorf("ListUsers should be sorted, got ids %v", func() []model.UserID {
			ids := make([]model.UserID, len(users))
			for i, u := range users {
				ids[i] = u.ID
			}
			return ids
		}())
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
