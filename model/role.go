package model

// RoleName is the unique name of a role.
type RoleName = string

// Role is a named set of permissions. A role inherits permissions of its
// parent roles transitively.
type Role struct {
	Name        RoleName     `json:"name"`
	Permissions []Permission `json:"permissions"`
	Parents     []RoleName   `json:"parents,omitempty"`
}

func (r *Role) HasParent(name RoleName) bool {
	for _, p := range r.Parents {
		if p == name {
			return true
		}
	}
	return false
}

func (r *Role) HasPermission(p Permission) bool {
	for _, granted := range r.Permissions {
		if granted.Matches(p) {
			return true
		}
	}
	return false
}
