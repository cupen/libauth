// Package libauth implements a multi-role permission system (RBAC).
//
// Core concepts:
//
//	User       — a subject identified by a unique ID, holding one or more roles.
//	Role       — a named collection of permissions; may inherit from parent roles.
//	Permission — a "resource:action" string such as "article:create".
//	             Wildcards are supported per segment ("article:*") and globally ("*").
//
// A user is granted a permission when ANY of its roles (including roles
// inherited transitively through parent roles) matches the permission, or
// when the user holds the permission directly.
package libauth

import (
	"strings"
)

// UserID is the unique identifier of a user.
type UserID = string

// RoleName is the unique name of a role.
type RoleName = string

// Permission is a "resource:action" pair, e.g. "article:create", "user:read".
//
// Wildcards:
//   - "*" alone grants every permission.
//   - A trailing (or any) segment may be "*", e.g. "article:*" matches
//     "article:create", "article:delete", ... .
type Permission string

// Wildcard matches any single permission segment.
const Wildcard = "*"

// Matches reports whether the permission p grants the required permission.
// p acts as the pattern (what a role grants), required acts as the concrete
// permission being checked.
func (p Permission) Matches(required Permission) bool {
	if p == required {
		return true
	}
	if p == Wildcard {
		return true
	}

	pattern := strings.Split(string(p), ":")
	want := strings.Split(string(required), ":")

	// A global wildcard also covers a different number of segments.
	if len(pattern) != len(want) {
		for _, seg := range pattern {
			if seg == Wildcard {
				return true
			}
		}
		return false
	}

	for i := range pattern {
		if pattern[i] != Wildcard && pattern[i] != want[i] {
			return false
		}
	}
	return true
}

// MatchesAny reports whether p grants any of the required permissions.
func (p Permission) MatchesAny(required ...Permission) bool {
	for _, r := range required {
		if p.Matches(r) {
			return true
		}
	}
	return false
}

// Valid reports whether the permission is well-formed (non-empty, and no
// empty segments such as "article:" or ":read").
func (p Permission) Valid() bool {
	if p == "" {
		return false
	}
	for _, seg := range strings.Split(string(p), ":") {
		if seg == "" {
			return false
		}
	}
	return true
}

// User is a subject that holds multiple roles.
type User struct {
	ID UserID `json:"id"`
	// Roles holds the roles directly assigned to the user. Effective
	// permissions may include roles inherited by these roles.
	Roles []RoleName `json:"roles"`
	// Direct holds permissions granted to the user directly, bypassing roles.
	Direct []Permission `json:"direct,omitempty"`
}

// Role is a named set of permissions. A role may inherit the permissions of
// its parent roles transitively.
type Role struct {
	Name RoleName `json:"name"`
	// Permissions granted by this role.
	Permissions []Permission `json:"permissions"`
	// Parents are role names whose permissions this role inherits.
	Parents []RoleName `json:"parents,omitempty"`
}

// HasParent reports whether the role declares the given parent.
func (r *Role) HasParent(name RoleName) bool {
	for _, p := range r.Parents {
		if p == name {
			return true
		}
	}
	return false
}

// HasPermission reports whether the role grants the permission directly
// (without considering inherited roles).
func (r *Role) HasPermission(p Permission) bool {
	for _, granted := range r.Permissions {
		if granted.Matches(p) {
			return true
		}
	}
	return false
}
