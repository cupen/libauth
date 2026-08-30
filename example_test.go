package libauth_test

// Example functions are runnable documentation: `go test` executes them and
// verifies the printed output, and godoc renders them next to the API they
// demonstrate.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/cupen/libauth"
)

// perm parses a "resource:action" string for the examples.
func perm(s string) libauth.Permission {
	p, err := libauth.ParsePermission(s)
	if err != nil {
		panic(err)
	}
	return p
}

// A user may hold several roles at once; effective permissions are the
// union of every role's permissions.
func Example() {
	e := libauth.New()

	_ = e.CreateRole("editor", []libauth.Permission{
		perm("article:create"), perm("article:edit"), perm("article:read"),
	}, "")
	_ = e.CreateRole("viewer", []libauth.Permission{perm("article:read")}, "")
	_ = e.CreateUser("bob", "editor", "viewer")

	fmt.Println(e.Check("bob", perm("article:create")))
	fmt.Println(e.Check("bob", perm("article:read")))
	fmt.Println(e.Check("bob", perm("article:delete")))

	// Output:
	// <nil>
	// <nil>
	// libauth: user "bob" lacks permission "article:delete" (roles: [editor viewer])
}

// Roles may inherit from parent roles; permissions flow down the chain.
func ExampleEnforcer_RolesFor() {
	e := libauth.New()

	_ = e.CreateRole("editor", []libauth.Permission{perm("article:create"), perm("article:read")}, "")
	_ = e.CreateRole("publisher", []libauth.Permission{perm("article:publish")}, "editor")
	_ = e.CreateUser("dave", "publisher")

	roles, _ := e.RolesFor("dave")
	fmt.Println(roles)

	fmt.Println(e.Check("dave", perm("article:publish")))
	fmt.Println(e.Check("dave", perm("article:create")))
	fmt.Println(e.Check("dave", perm("article:delete")))

	// Output:
	// [editor publisher]
	// <nil>
	// <nil>
	// libauth: user "dave" lacks permission "article:delete" (roles: [editor publisher])
}

// Permissions are {Resource, Action} structs; either field may be "*" for a
// wildcard match.
func Example_wildcards() {
	e := libauth.New()

	_ = e.CreateRole("admin", []libauth.Permission{perm("*")}, "")
	_ = e.CreateRole("article-admin", []libauth.Permission{perm("article:*")}, "")
	_ = e.CreateUser("alice", "admin")
	_ = e.CreateUser("oak", "article-admin")

	for _, c := range []struct {
		user string
		perm libauth.Permission
	}{
		{"alice", perm("user:delete")},
		{"oak", perm("article:delete")},
		{"oak", perm("user:delete")},
	} {
		ok, _ := e.HasPermission(c.user, c.perm)
		fmt.Println(ok)
	}

	// Output:
	// true
	// true
	// false
}

// Roles and assignments can change at any time; checks see the new state
// immediately.
func ExampleEnforcer_AssignRole() {
	e := libauth.New()

	_ = e.CreateRole("viewer", []libauth.Permission{perm("article:read")}, "")
	_ = e.CreateRole("editor", []libauth.Permission{perm("article:create"), perm("article:read")}, "")
	_ = e.CreateUser("carol", "viewer")

	fmt.Println(e.Check("carol", perm("article:create")))

	_ = e.AssignRole("carol", "editor")
	fmt.Println(e.Check("carol", perm("article:create")))

	_ = e.RevokeRole("carol", "editor")
	fmt.Println(e.Check("carol", perm("article:create")))

	// Output:
	// libauth: user "carol" lacks permission "article:create" (roles: [viewer])
	// <nil>
	// libauth: user "carol" lacks permission "article:create" (roles: [viewer])
}

// A single user can be granted one-off permissions without touching any role.
func ExampleEnforcer_GrantDirectPermission() {
	e := libauth.New()

	_ = e.CreateRole("viewer", []libauth.Permission{perm("article:read")}, "")
	_ = e.CreateUser("carol", "viewer")

	_ = e.GrantDirectPermission("carol", perm("article:comment"))
	fmt.Println(e.Check("carol", perm("article:comment")))

	_ = e.RevokeDirectPermission("carol", perm("article:comment"))
	fmt.Println(e.Check("carol", perm("article:comment")))

	// Output:
	// <nil>
	// libauth: user "carol" lacks permission "article:comment" (roles: [viewer])
}

// PermissionsFor lists every permission a user effectively holds, merged
// from all (inherited) roles and direct grants.
func ExampleEnforcer_PermissionsFor() {
	e := libauth.New()

	_ = e.CreateRole("editor", []libauth.Permission{
		perm("article:create"), perm("article:edit"), perm("article:read"), perm("whoami:read"),
	}, "")
	_ = e.CreateRole("viewer", []libauth.Permission{perm("article:read"), perm("whoami:read")}, "")
	_ = e.CreateUser("bob", "editor", "viewer")
	_ = e.GrantDirectPermission("bob", perm("article:comment"))

	perms, _ := e.PermissionsFor("bob")
	fmt.Println(perms)

	// Output:
	// [article:comment article:create article:edit article:read whoami:read]
}

// Check returns nil on success and typed, inspectable errors on failure.
func ExampleEnforcer_Check() {
	e := libauth.New()

	_ = e.CreateRole("viewer", []libauth.Permission{perm("article:read")}, "")
	_ = e.CreateUser("carol", "viewer")

	fmt.Println(e.Check("carol", perm("article:read")))

	err := e.Check("carol", perm("article:delete"))
	var denied *libauth.PermissionDeniedError
	if errors.As(err, &denied) {
		fmt.Println("denied for:", denied.Required, "roles:", denied.Roles)
	}

	fmt.Println(e.Check("ghost", perm("article:read")))

	// Output:
	// <nil>
	// denied for: article:delete roles: [viewer]
	// libauth: user not found
}

// Middleware guards http handlers; the identified user is available through
// UserFromContext inside the handler.
func ExampleNewMiddleware() {
	e := libauth.New()

	_ = e.CreateRole("editor", []libauth.Permission{perm("article:create"), perm("article:read")}, "")
	_ = e.CreateUser("bob", "editor")

	mw, _ := libauth.NewMiddleware(e, libauth.HeaderIdentity(""))

	create := mw.Require(perm("article:create"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := libauth.UserFromContext(r.Context())
		fmt.Fprintf(w, "article created by %s", u.ID)
	}))

	req := httptest.NewRequest(http.MethodPost, "/articles", nil)
	req.Header.Set("X-User-ID", "bob")
	rec := httptest.NewRecorder()
	create.ServeHTTP(rec, req)
	fmt.Println(rec.Code, rec.Body.String())

	req = httptest.NewRequest(http.MethodPost, "/articles", nil)
	req.Header.Set("X-User-ID", "carol")
	rec = httptest.NewRecorder()
	create.ServeHTTP(rec, req)
	fmt.Println(rec.Code)

	// Output:
	// 200 article created by bob
	// 401
}
