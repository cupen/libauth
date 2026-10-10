package model

// RoleID is the unique identifier of a role.
type RoleID = string

// Role is a named set of permissions; it inherits from a single Parent.
type Role struct {
	Name        RoleID       `json:"name"`
	Permissions []Permission `json:"permissions"`
	Parent      RoleID       `json:"parent,omitempty"`
}

func (r *Role) HasPermission(p Permission) bool {
	for _, g := range r.Permissions {
		if g.Matches(p) {
			return true
		}
	}
	return false
}
