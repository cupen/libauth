package model

// RoleID is the unique identifier of a role.
type RoleID = string

// Role is a named set of permissions; it inherits from a single Parent.
type Role struct {
	Name        RoleID       `json:"name"`
	Permissions []Permission `json:"permissions"`
	Parent      RoleID       `json:"parent,omitempty"`
}

// HasPermission reports whether this role's own declared permissions cover p,
// including wildcard patterns. It does not consider inherited permissions
// from Parent, other roles a user may hold, or a user's direct grants; for
// the full effective answer use Enforcer.Check or Enforcer.HasPermission.
func (r *Role) HasPermission(p Permission) bool {
	for _, g := range r.Permissions {
		if g.Matches(p) {
			return true
		}
	}
	return false
}
