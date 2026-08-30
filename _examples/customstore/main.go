// Command customstore shows how to plug a custom persistence layer into
// libauth by implementing the Store interface. This demo persists the RBAC
// world to a JSON file: it builds roles and users through one enforcer, then
// reloads the same file into a second, independent enforcer.
//
// Note how thin the Store implementation is: the contract only covers
// whole-object CRUD — relationship mutations are handled by authz.Enforcer.
//
//	go run ./_examples/customstore
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cupen/libauth"
)

// fileStore persists the RBAC world as JSON after every mutation. A
// production store would implement Store directly against a database.
type fileStore struct {
	*libauth.MemoryStore
	path string
}

func newFileStore(path string) (*fileStore, error) {
	fs := &fileStore{MemoryStore: libauth.NewMemoryStore(), path: path}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fs, nil
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

// Read operations are inherited from the embedded MemoryStore; each mutation
// writes through to disk.

func (fs *fileStore) CreateUser(u *libauth.User) error {
	if err := fs.MemoryStore.CreateUser(u); err != nil {
		return err
	}
	return fs.save()
}

func (fs *fileStore) UpdateUser(u *libauth.User) error {
	if err := fs.MemoryStore.UpdateUser(u); err != nil {
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

func main() {
	dir, err := os.MkdirTemp("", "libauth-customstore-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "rbac.json")
	fmt.Println("data file:", path)

	store, err := newFileStore(path)
	if err != nil {
		panic(err)
	}
	m := libauth.New(libauth.WithStore(store))
	must(m.CreateRole("editor", []libauth.Permission{
		{Resource: "article", Action: "create"},
		{Resource: "article", Action: "read"},
	}, ""))
	must(m.CreateRole("viewer", []libauth.Permission{
		{Resource: "article", Action: "read"},
		{Resource: "whoami", Action: "read"},
	}, ""))
	must(m.CreateUser("bob", "editor", "viewer"))

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

	bobOK := libauth.Permission{Resource: "article", Action: "create"}
	daveOK := libauth.Permission{Resource: "article", Action: "read"}
	fmt.Println("\nbob may still create articles:", m2.Check("bob", bobOK) == nil)
	fmt.Println("dave is unknown after reload:", m2.Check("dave", daveOK))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
