// Command basic demonstrates the core libauth flows without any HTTP layer:
// defining roles, multi-role users, role inheritance, wildcards and runtime
// authorization changes.
//
// Run it with:
//
//	go run ./examples/basic
package main

import (
	"errors"
	"fmt"

	"libauth"
)

func main() {
	m := libauth.New()

	// ---- 1. Define roles --------------------------------------------------
	must(m.CreateRole("viewer", []libauth.Permission{"article:read", "whoami:read"}))
	must(m.CreateRole("editor", []libauth.Permission{
		"article:create", "article:edit", "article:read", "whoami:read",
	}))
	// publisher inherits every editor permission and adds its own.
	must(m.CreateRole("publisher", []libauth.Permission{"article:publish"}, "editor"))
	// The admin wildcard matches every permission.
	must(m.CreateRole("admin", []libauth.Permission{"*"}))

	// ---- 2. Users, each with one or more roles -----------------------------
	must(m.CreateUser("carol", "viewer"))
	must(m.CreateUser("bob", "editor", "viewer")) // multi-role: union of both
	must(m.CreateUser("dave", "publisher"))       // inherits editor
	must(m.CreateUser("alice", "admin"))

	fmt.Println("== roles ==")
	for _, u := range []string{"carol", "bob", "dave", "alice"} {
		roles, _ := m.RolesFor(u)
		fmt.Printf("%-6s effective roles: %v\n", u, roles)
	}

	// ---- 3. Permission checks ----------------------------------------------
	fmt.Println("\n== checks ==")
	for _, c := range []struct {
		user string
		perm libauth.Permission
	}{
		{"carol", "article:read"},
		{"carol", "article:create"},
		{"bob", "article:create"},
		{"bob", "article:delete"},
		{"dave", "article:publish"},
		{"dave", "article:edit"}, // inherited from editor
		{"alice", "user:delete"}, // via the "*" wildcard
	} {
		verdict(m, c.user, c.perm)
	}

	// ---- 4. Runtime changes -------------------------------------------------
	fmt.Println("\n== runtime changes ==")

	// Promote carol: she gains every editor permission at once.
	must(m.AssignRole("carol", "editor"))
	verdict(m, "carol", "article:create")

	// Grant a permission to a whole role: every holder gains it instantly.
	must(m.GrantPermission("viewer", "article:comment"))
	verdict(m, "carol", "article:comment")

	// One-off permission for a single user, no role involved.
	must(m.GrantDirectPermission("carol", "article:archive"))
	verdict(m, "carol", "article:archive")

	// Demote again: editor permissions disappear, everything else remains.
	must(m.RevokeRole("carol", "editor"))
	verdict(m, "carol", "article:create")

	fmt.Println("\n== carol's effective permissions ==")
	perms, _ := m.PermissionsFor("carol")
	fmt.Println(perms)
}

func verdict(m *libauth.Manager, user string, perm libauth.Permission) {
	err := m.Check(user, perm)
	switch {
	case err == nil:
		fmt.Printf("%-6s %-17s allowed\n", user, perm)
	case errors.Is(err, libauth.ErrPermissionDenied):
		fmt.Printf("%-6s %-17s denied\n", user, perm)
	default:
		fmt.Printf("%-6s %-17s error: %v\n", user, perm, err)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
