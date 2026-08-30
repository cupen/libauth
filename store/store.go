// Package store defines the persistence contract of libauth and ships an
// in-memory reference implementation (MemoryStore).
//
// The contract is intentionally narrow: persist whole User and Role
// objects and look them up. Relationships (which roles a user has,
// which permissions a role grants, role inheritance) are owned by the
// business layer (authz.Enforcer) and maintained by load → mutate
// slices → UpdateUser / UpdateRole.
package store

import "github.com/cupen/libauth/model"

// Store persists whole User / Role objects. All methods must be safe for
// concurrent use; returned objects must be defensive copies.
type Store interface {
	// ---- users ----
	CreateUser(u *model.User) error
	UpdateUser(u *model.User) error
	GetUser(id model.UserID) (*model.User, error)
	DeleteUser(id model.UserID) error
	ListUsers() ([]*model.User, error)

	// ---- roles ----
	CreateRole(r *model.Role) error
	UpdateRole(r *model.Role) error
	GetRole(name model.RoleName) (*model.Role, error)
	DeleteRole(name model.RoleName) error
	ListRoles() ([]*model.Role, error)
}
