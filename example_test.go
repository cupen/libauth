package libauth_test

// The Example functions below are runnable documentation: `go test` executes
// them and verifies the printed output, and godoc renders them next to the
// API they demonstrate.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"libauth"
)

// A user may hold several roles at once; his effective permissions are the
// union of every role's permissions.
func Example() {
	m := libauth.New()

	_ = m.CreateRole("editor", []libauth.Permission{"article:create", "article:edit", "article:read"})
	_ = m.CreateRole("viewer", []libauth.Permission{"article:read"})

	// bob holds TWO roles.
	_ = m.CreateUser("bob", "editor", "viewer")

	fmt.Println(m.Check("bob", "article:create")) // granted by editor
	fmt.Println(m.Check("bob", "article:read"))   // granted by either role
	fmt.Println(m.Check("bob", "article:delete")) // granted by no role

	// Output:
	// <nil>
	// <nil>
	// libauth: user "bob" lacks permission "article:delete" (roles: [editor viewer])
}

// Roles may inherit from parent roles; permissions flow down the chain.
func ExampleManager_RolesFor() {
	m := libauth.New()

	_ = m.CreateRole("editor", []libauth.Permission{"article:create", "article:read"})
	// publisher = editor + the publish right.
	_ = m.CreateRole("publisher", []libauth.Permission{"article:publish"}, "editor")
	_ = m.CreateUser("dave", "publisher")

	roles, _ := m.RolesFor("dave")
	fmt.Println(roles)

	fmt.Println(m.Check("dave", "article:publish")) // own permission
	fmt.Println(m.Check("dave", "article:create"))  // inherited from editor
	fmt.Println(m.Check("dave", "article:delete"))  // nowhere in the chain

	// Output:
	// [editor publisher]
	// <nil>
	// <nil>
	// libauth: user "dave" lacks permission "article:delete" (roles: [editor publisher])
}

// Permissions are "resource:action" strings; wildcards work per segment or
// globally.
func Example_wildcards() {
	m := libauth.New()

	_ = m.CreateRole("admin", []libauth.Permission{"*"})                 // everything
	_ = m.CreateRole("article-admin", []libauth.Permission{"article:*"}) // every article action
	_ = m.CreateUser("alice", "admin")
	_ = m.CreateUser("oak", "article-admin")

	for _, c := range []struct {
		user string
		perm libauth.Permission
	}{
		{"alice", "user:delete"},
		{"oak", "article:delete"},
		{"oak", "user:delete"}, // outside the article-admin scope
	} {
		ok, _ := m.HasPermission(c.user, c.perm)
		fmt.Println(ok)
	}

	// Output:
	// true
	// true
	// false
}

// Roles and assignments can change at any time; checks see the new state
// immediately.
func ExampleManager_AssignRole() {
	m := libauth.New()

	_ = m.CreateRole("viewer", []libauth.Permission{"article:read"})
	_ = m.CreateRole("editor", []libauth.Permission{"article:create", "article:read"})
	_ = m.CreateUser("carol", "viewer")

	fmt.Println(m.Check("carol", "article:create"))

	_ = m.AssignRole("carol", "editor") // promote...
	fmt.Println(m.Check("carol", "article:create"))

	_ = m.RevokeRole("carol", "editor") // ...and demote again
	fmt.Println(m.Check("carol", "article:create"))

	// Output:
	// libauth: user "carol" lacks permission "article:create" (roles: [viewer])
	// <nil>
	// libauth: user "carol" lacks permission "article:create" (roles: [viewer])
}

// Single users can be granted one-off permissions without touching any role.
func ExampleManager_GrantDirectPermission() {
	m := libauth.New()

	_ = m.CreateRole("viewer", []libauth.Permission{"article:read"})
	_ = m.CreateUser("carol", "viewer")

	_ = m.GrantDirectPermission("carol", "article:comment")
	fmt.Println(m.Check("carol", "article:comment"))

	_ = m.RevokeDirectPermission("carol", "article:comment")
	fmt.Println(m.Check("carol", "article:comment"))

	// Output:
	// <nil>
	// libauth: user "carol" lacks permission "article:comment" (roles: [viewer])
}

// PermissionsFor lists every permission a user effectively holds, merged
// from all (inherited) roles and direct grants.
func ExampleManager_PermissionsFor() {
	m := libauth.New()

	_ = m.CreateRole("editor", []libauth.Permission{"article:create", "article:edit", "article:read", "whoami:read"})
	_ = m.CreateRole("viewer", []libauth.Permission{"article:read", "whoami:read"})
	_ = m.CreateUser("bob", "editor", "viewer")
	_ = m.GrantDirectPermission("bob", "article:comment")

	perms, _ := m.PermissionsFor("bob")
	fmt.Println(perms)

	// Output:
	// [article:comment article:create article:edit article:read whoami:read]
}

// Check returns nil on success and typed, inspectable errors on failure.
func ExampleManager_Check() {
	m := libauth.New()

	_ = m.CreateRole("viewer", []libauth.Permission{"article:read"})
	_ = m.CreateUser("carol", "viewer")

	fmt.Println(m.Check("carol", "article:read"))

	err := m.Check("carol", "article:delete")
	var denied *libauth.PermissionDeniedError
	if errors.As(err, &denied) {
		fmt.Println("denied for:", denied.Required, "roles:", denied.Roles)
	}

	fmt.Println(m.Check("ghost", "article:read")) // unknown user

	// Output:
	// <nil>
	// denied for: article:delete roles: [viewer]
	// libauth: user not found
}

// Middleware guards http handlers; the identified user is available through
// UserFromContext inside the handler.
func ExampleNewMiddleware() {
	m := libauth.New()

	_ = m.CreateRole("editor", []libauth.Permission{"article:create", "article:read"})
	_ = m.CreateUser("bob", "editor")

	// Default identity: the X-User-ID header. Plug in JWT/session parsing
	// here for real deployments.
	mw, _ := libauth.NewMiddleware(m, libauth.HeaderIdentity(""))

	create := mw.Require("article:create")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := libauth.UserFromContext(r.Context())
		fmt.Fprintf(w, "article created by %s", u.ID)
	}))

	// bob passes the guard.
	req := httptest.NewRequest(http.MethodPost, "/articles", nil)
	req.Header.Set("X-User-ID", "bob")
	rec := httptest.NewRecorder()
	create.ServeHTTP(rec, req)
	fmt.Println(rec.Code, rec.Body.String())

	// carol has no account: rejected before reaching the handler.
	req = httptest.NewRequest(http.MethodPost, "/articles", nil)
	req.Header.Set("X-User-ID", "carol")
	rec = httptest.NewRecorder()
	create.ServeHTTP(rec, req)
	fmt.Println(rec.Code)

	// Output:
	// 200 article created by bob
	// 401
}
