// Command basic demonstrates the core libauth flows: roles, multi-role
// users, inheritance, wildcards and runtime changes.
//
//	go run ./_examples/basic
package main

import (
	"errors"
	"fmt"

	"github.com/cupen/libauth"
)

func main() {
	m := libauth.New()

	must(m.CreateRole("viewer", []libauth.Permission{
		libauth.Permission{Resource: "article", Action: "read"},
		libauth.Permission{Resource: "whoami", Action: "read"},
	}))
	must(m.CreateRole("editor", []libauth.Permission{
		{Resource: "article", Action: "create"},
		{Resource: "article", Action: "edit"},
		{Resource: "article", Action: "read"},
		{Resource: "whoami", Action: "read"},
	}))
	// publisher inherits every editor permission and adds its own.
	must(m.CreateRole("publisher",
		[]libauth.Permission{{Resource: "article", Action: "publish"}}, "editor"))
	must(m.CreateRole("admin", []libauth.Permission{{Resource: "*"}}))

	must(m.CreateUser("carol", "viewer"))
	must(m.CreateUser("bob", "editor", "viewer"))
	must(m.CreateUser("dave", "publisher"))
	must(m.CreateUser("alice", "admin"))

	fmt.Println("== roles ==")
	for _, u := range []string{"carol", "bob", "dave", "alice"} {
		roles, _ := m.RolesFor(u)
		fmt.Printf("%-6s effective roles: %v\n", u, roles)
	}

	fmt.Println("\n== checks ==")
	for _, c := range []struct {
		user string
		perm libauth.Permission
	}{
		{"carol", libauth.Permission{Resource: "article", Action: "read"}},
		{"carol", libauth.Permission{Resource: "article", Action: "create"}},
		{"bob", libauth.Permission{Resource: "article", Action: "create"}},
		{"bob", libauth.Permission{Resource: "article", Action: "delete"}},
		{"dave", libauth.Permission{Resource: "article", Action: "publish"}},
		{"dave", libauth.Permission{Resource: "article", Action: "edit"}}, // inherited from editor
		{"alice", libauth.Permission{Resource: "user", Action: "delete"}}, // via the "*" wildcard
	} {
		verdict(m, c.user, c.perm)
	}

	fmt.Println("\n== runtime changes ==")

	must(m.AssignRole("carol", "editor"))
	verdict(m, "carol", libauth.Permission{Resource: "article", Action: "create"})

	must(m.GrantPermission("viewer", libauth.Permission{Resource: "article", Action: "comment"}))
	verdict(m, "carol", libauth.Permission{Resource: "article", Action: "comment"})

	must(m.GrantDirectPermission("carol", libauth.Permission{Resource: "article", Action: "archive"}))
	verdict(m, "carol", libauth.Permission{Resource: "article", Action: "archive"})

	must(m.RevokeRole("carol", "editor"))
	verdict(m, "carol", libauth.Permission{Resource: "article", Action: "create"})

	fmt.Println("\n== carol's effective permissions ==")
	perms, _ := m.PermissionsFor("carol")
	fmt.Println(perms)
}

func verdict(m *libauth.Enforcer, user string, perm libauth.Permission) {
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
