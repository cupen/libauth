// Package model defines the core RBAC data types: users, roles and
// permissions. The types are free of persistence and HTTP concerns so they
// can be serialized, cached or transported as-is.
package model

// UserID is the unique identifier of a user.
type UserID = string

// User is a subject that holds multiple roles and optional direct
// permissions.
type User struct {
	ID     UserID       `json:"id"`
	Roles  []RoleName   `json:"roles"`
	Direct []Permission `json:"direct,omitempty"`
}
