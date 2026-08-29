package libauth

// Store is the persistence contract of the permission system. The in-memory
// implementation (MemoryStore) ships with the package; implement this
// interface to back libauth with a database or remote service.
//
// All methods should be safe for concurrent use.
//
// Implementations may return the sentinel errors declared in this package
// (e.g. ErrUserNotFound, ErrRoleNotFound) where appropriate.
type Store interface {
	// ---- users ----

	CreateUser(u *User) error
	GetUser(id UserID) (*User, error)
	DeleteUser(id UserID) error
	// ListUsers returns all users; an empty slice means no users.
	ListUsers() ([]*User, error)

	// ---- role assignment ----

	// AssignRole adds the role to the user's role set (idempotent).
	AssignRole(id UserID, role RoleName) error
	// RevokeRole removes the role from the user's role set (idempotent).
	RevokeRole(id UserID, role RoleName) error

	// ---- direct user permissions ----

	GrantUserPermission(id UserID, p Permission) error
	RevokeUserPermission(id UserID, p Permission) error

	// ---- roles ----

	// CreateRole inserts a new role; it must fail with ErrRoleExists when
	// the role name is already taken.
	CreateRole(r *Role) error
	// UpdateRole replaces an existing role's definition (permissions and
	// parents) while keeping its name.
	UpdateRole(r *Role) error
	GetRole(name RoleName) (*Role, error)
	DeleteRole(name RoleName) error
	// ListRoles returns all roles; an empty slice means no roles.
	ListRoles() ([]*Role, error)

	// ---- role permissions ----

	// GrantPermission adds a permission to the role (idempotent).
	GrantPermission(role RoleName, p Permission) error
	// RevokePermission removes a permission from the role (idempotent).
	RevokePermission(role RoleName, p Permission) error
}
