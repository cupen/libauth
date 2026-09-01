package model

// RoleName / RoleID are the unique name of a role; both spellings are kept
// so callers can pick the one that reads best at the call site.
type (
	RoleName = string
	RoleID   = RoleName
)

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