package model

// RoleName is the unique name of a role.
type RoleName = string

// RoleID is the unique name of a role. Kept as a synonym for RoleName so
// both spellings are available to callers.
type RoleID = RoleName

// Role is a named set of permissions. A role inherits permissions of its
// single parent (if any); a user needing to combine several permission sets
// simply holds several roles.
type Role struct {
	Name        RoleID       `json:"name"`
	Permissions []Permission `json:"permissions"`
	// Parent is the role this role inherits from; empty means no parent.
	Parent RoleID `json:"parent,omitempty"`
}

func (r *Role) HasPermission(p Permission) bool {
	for _, granted := range r.Permissions {
		if granted.Matches(p) {
			return true
		}
	}
	return false
}
