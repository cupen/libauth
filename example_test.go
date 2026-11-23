package libauth_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/cupen/libauth"
)

// A user may hold several roles at once; effective permissions are the
// union of every role's permissions.
func Example() {
	e := libauth.New()

	_ = e.CreateRole("editor", []libauth.Permission{
		libauth.Perm("article", "create"), libauth.Perm("article", "edit"), libauth.Perm("article", "read"),
	}, "")
	_ = e.CreateRole("viewer", []libauth.Permission{libauth.Perm("article", "read")}, "")
	_ = e.CreateUser("bob", "editor", "viewer")

	fmt.Println(e.Check("bob", libauth.Perm("article", "create")))
	fmt.Println(e.Check("bob", libauth.Perm("article", "read")))
	fmt.Println(e.Check("bob", libauth.Perm("article", "delete")))

	// Output:
	// <nil>
	// <nil>
	// libauth: user "bob" lacks permission "article:delete" (roles: [editor viewer])
}

// Roles may inherit from parent roles; permissions flow down the chain.
func ExampleEnforcer_RolesFor() {
	e := libauth.New()

	_ = e.CreateRole("editor", []libauth.Permission{libauth.Perm("article", "create"), libauth.Perm("article", "read")}, "")
	_ = e.CreateRole("publisher", []libauth.Permission{libauth.Perm("article", "publish")}, "editor")
	_ = e.CreateUser("dave", "publisher")

	roles, _ := e.RolesFor("dave")
	fmt.Println(roles)

	fmt.Println(e.Check("dave", libauth.Perm("article", "publish")))
	fmt.Println(e.Check("dave", libauth.Perm("article", "create")))
	fmt.Println(e.Check("dave", libauth.Perm("article", "delete")))

	// Output:
	// [editor publisher]
	// <nil>
	// <nil>
	// libauth: user "dave" lacks permission "article:delete" (roles: [editor publisher])
}

// Permissions are resource/action pairs; either side may be "*" for a
// wildcard match.
func Example_wildcards() {
	e := libauth.New()

	_ = e.CreateRole("admin", []libauth.Permission{libauth.Perm("*", "")}, "")
	_ = e.CreateRole("article-admin", []libauth.Permission{libauth.Perm("article", "*")}, "")
	_ = e.CreateUser("alice", "admin")
	_ = e.CreateUser("oak", "article-admin")

	for _, c := range []struct {
		user string
		perm libauth.Permission
	}{
		{"alice", libauth.Perm("user", "delete")},
		{"oak", libauth.Perm("article", "delete")},
		{"oak", libauth.Perm("user", "delete")},
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

	_ = e.CreateRole("viewer", []libauth.Permission{libauth.Perm("article", "read")}, "")
	_ = e.CreateRole("editor", []libauth.Permission{libauth.Perm("article", "create"), libauth.Perm("article", "read")}, "")
	_ = e.CreateUser("carol", "viewer")

	fmt.Println(e.Check("carol", libauth.Perm("article", "create")))

	_ = e.AssignRole("carol", "editor")
	fmt.Println(e.Check("carol", libauth.Perm("article", "create")))

	_ = e.RevokeRole("carol", "editor")
	fmt.Println(e.Check("carol", libauth.Perm("article", "create")))

	// Output:
	// libauth: user "carol" lacks permission "article:create" (roles: [viewer])
	// <nil>
	// libauth: user "carol" lacks permission "article:create" (roles: [viewer])
}

// A single user can be granted one-off permissions without touching any role.
func ExampleEnforcer_GrantDirectPermission() {
	e := libauth.New()

	_ = e.CreateRole("viewer", []libauth.Permission{libauth.Perm("article", "read")}, "")
	_ = e.CreateUser("carol", "viewer")

	_ = e.GrantDirectPermission("carol", libauth.Perm("article", "comment"))
	fmt.Println(e.Check("carol", libauth.Perm("article", "comment")))

	_ = e.RevokeDirectPermission("carol", libauth.Perm("article", "comment"))
	fmt.Println(e.Check("carol", libauth.Perm("article", "comment")))

	// Output:
	// <nil>
	// libauth: user "carol" lacks permission "article:comment" (roles: [viewer])
}

// PermissionsFor lists every permission a user effectively holds, merged
// from all (inherited) roles and direct grants.
func ExampleEnforcer_PermissionsFor() {
	e := libauth.New()

	_ = e.CreateRole("editor", []libauth.Permission{
		libauth.Perm("article", "create"), libauth.Perm("article", "edit"), libauth.Perm("article", "read"), libauth.Perm("whoami", "read"),
	}, "")
	_ = e.CreateRole("viewer", []libauth.Permission{libauth.Perm("article", "read"), libauth.Perm("whoami", "read")}, "")
	_ = e.CreateUser("bob", "editor", "viewer")
	_ = e.GrantDirectPermission("bob", libauth.Perm("article", "comment"))

	perms, _ := e.PermissionsFor("bob")
	fmt.Println(perms)

	// Output:
	// [article:comment article:create article:edit article:read whoami:read]
}

// Check returns nil on success and typed, inspectable errors on failure.
func ExampleEnforcer_Check() {
	e := libauth.New()

	_ = e.CreateRole("viewer", []libauth.Permission{libauth.Perm("article", "read")}, "")
	_ = e.CreateUser("carol", "viewer")

	fmt.Println(e.Check("carol", libauth.Perm("article", "read")))

	err := e.Check("carol", libauth.Perm("article", "delete"))
	var denied *libauth.PermissionDeniedError
	if errors.As(err, &denied) {
		fmt.Println("denied for:", denied.Required, "roles:", denied.Roles)
	}

	fmt.Println(e.Check("ghost", libauth.Perm("article", "read")))

	// Output:
	// <nil>
	// denied for: article:delete roles: [viewer]
	// libauth: user not found
}

// Middleware guards http handlers; the identified user is available through
// UserFromContext inside the handler.
func ExampleNewMiddleware() {
	e := libauth.New()

	_ = e.CreateRole("editor", []libauth.Permission{libauth.Perm("article", "create"), libauth.Perm("article", "read")}, "")
	_ = e.CreateUser("bob", "editor")

	mw, _ := libauth.NewMiddleware(e, libauth.HeaderIdentity(""))

	create := mw.Require(libauth.Perm("article", "create"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
