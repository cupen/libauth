package model

// UserID is the unique identifier of a user.
type UserID = string

// User holds multiple roles and optional direct permissions.
type User struct {
	ID     UserID       `json:"id"`
	Roles  []RoleID     `json:"roles"`
	Direct []Permission `json:"direct,omitempty"`
}
