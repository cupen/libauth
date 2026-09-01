// Package store defines libauth's persistence contract and ships an
// in-memory reference implementation (MemoryStore).
//
// Relationships (which roles a user has, role inheritance) are owned by
// the authz layer; Store only persists whole User / Role objects.
package store

import "github.com/cupen/libauth/model"

// Store persists whole User / Role objects. Methods must be safe for
// concurrent use; returned objects must be defensive copies.
type Store interface {
	CreateUser(u *model.User) error
	UpdateUser(u *model.User) error
	GetUser(id model.UserID) (*model.User, error)
	DeleteUser(id model.UserID) error
	ListUsers() ([]*model.User, error)

	CreateRole(r *model.Role) error
	UpdateRole(r *model.Role) error
	GetRole(name model.RoleID) (*model.Role, error)
	DeleteRole(name model.RoleID) error
	ListRoles() ([]*model.Role, error)
}