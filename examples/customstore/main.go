// Command customstore shows how to plug a custom persistence layer into
// libauth by implementing the Store interface. This demo persists the RBAC
// world to a JSON file: it builds roles and users through one manager, then
// reloads the same file into a second, independent manager.
//
// Run it with:
//
//	go run ./examples/customstore
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"libauth"
)

// fileStore persists the RBAC world as JSON after every mutation. The
// in-memory bookkeeping is delegated to an embedded MemoryStore; a production
// store would implement the same Store interface directly against a database.
type fileStore struct {
	*libauth.MemoryStore
	path string
}

// newFileStore opens (and hydrates from) a JSON file, starting empty when the
// file does not exist yet.
func newFileStore(path string) (*fileStore, error) {
	fs := &fileStore{MemoryStore: libauth.NewMemoryStore(), path: path}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fs, nil // first run
	}
	if err != nil {
		return nil, err
	}

	var dump struct {
		Users []*libauth.User `json:"users"`
		Roles []*libauth.Role `json:"roles"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return nil, err
	}
	for _, r := range dump.Roles {
		if err := fs.MemoryStore.CreateRole(r); err != nil && !errors.Is(err, libauth.ErrRoleExists) {
			return nil, err
		}
	}
	for _, u := range dump.Users {
		if err := fs.MemoryStore.CreateUser(u); err != nil && !errors.Is(err, libauth.ErrUserExists) {
			return nil, err
		}
	}
	return fs, nil
}

// save serializes the current world; called after every successful mutation.
func (fs *fileStore) save() error {
	users, err := fs.MemoryStore.ListUsers()
	if err != nil {
		return err
	}
	roles, err := fs.MemoryStore.ListRoles()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(struct {
		Users []*libauth.User `json:"users"`
		Roles []*libauth.Role `json:"roles"`
	}{users, roles}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(fs.path, raw, 0o600)
}

// Read operations (GetUser, ListUsers, GetRole, ListRoles) are inherited from
// the embedded MemoryStore; every mutation below writes through to disk.

func (fs *fileStore) CreateUser(u *libauth.User) error {
	if err := fs.MemoryStore.CreateUser(u); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) DeleteUser(id libauth.UserID) error {
	if err := fs.MemoryStore.DeleteUser(id); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) AssignRole(id libauth.UserID, role libauth.RoleName) error {
	if err := fs.MemoryStore.AssignRole(id, role); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) RevokeRole(id libauth.UserID, role libauth.RoleName) error {
	if err := fs.MemoryStore.RevokeRole(id, role); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) GrantUserPermission(id libauth.UserID, p libauth.Permission) error {
	if err := fs.MemoryStore.GrantUserPermission(id, p); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) RevokeUserPermission(id libauth.UserID, p libauth.Permission) error {
	if err := fs.MemoryStore.RevokeUserPermission(id, p); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) CreateRole(r *libauth.Role) error {
	if err := fs.MemoryStore.CreateRole(r); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) UpdateRole(r *libauth.Role) error {
	if err := fs.MemoryStore.UpdateRole(r); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) DeleteRole(name libauth.RoleName) error {
	if err := fs.MemoryStore.DeleteRole(name); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) GrantPermission(role libauth.RoleName, p libauth.Permission) error {
	if err := fs.MemoryStore.GrantPermission(role, p); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) RevokePermission(role libauth.RoleName, p libauth.Permission) error {
	if err := fs.MemoryStore.RevokePermission(role, p); err != nil {
		return err
	}
	return fs.save()
}

func main() {
	dir, err := os.MkdirTemp("", "libauth-customstore-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "rbac.json")
	fmt.Println("data file:", path)

	// ---- first run: seed the world through the file-backed store ----------
	store, err := newFileStore(path)
	if err != nil {
		panic(err)
	}
	m := libauth.New(libauth.WithStore(store))
	must(m.CreateRole("editor", []libauth.Permission{"article:create", "article:read"}))
	must(m.CreateRole("viewer", []libauth.Permission{"article:read", "whoami:read"}))
	must(m.CreateUser("bob", "editor", "viewer"))

	// ---- second run: a fresh manager hydrates from the same JSON file -----
	reloaded, err := newFileStore(path)
	if err != nil {
		panic(err)
	}
	m2 := libauth.New(libauth.WithStore(reloaded))

	fmt.Println("\nafter reload from disk:")
	roles, _ := m2.ListRoles()
	for _, r := range roles {
		fmt.Printf("  role %-8s perms=%v\n", r.Name, r.Permissions)
	}
	users, _ := m2.ListUsers()
	for _, u := range users {
		fmt.Printf("  user %-8s roles=%v\n", u.ID, u.Roles)
	}

	fmt.Println("\nbob may still create articles:", m2.Check("bob", "article:create") == nil)
	fmt.Println("dave is unknown after reload:", m2.Check("dave", "article:read"))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
