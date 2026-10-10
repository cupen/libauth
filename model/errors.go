package model

import (
	"errors"
	"fmt"
)

var (
	ErrPermissionDenied  = errors.New("libauth: permission denied")
	ErrInvalidPermission = errors.New("libauth: invalid permission")
)

// PermissionDeniedError carries the context of a failed authorization.
// Exactly one of Required, RequiredAny or RequiredRole describes what the
// user lacked; the others stay zero.
type PermissionDeniedError struct {
	UserID   UserID
	User     *User
	Required Permission // the permission the call demanded
	// RequiredAny is the list the call accepted any one of.
	RequiredAny []Permission
	// RequiredRole is the role the call demanded.
	RequiredRole RoleID
	Roles        []RoleID
}

func (e *PermissionDeniedError) Error() string {
	switch {
	case e.RequiredRole != "":
		return fmt.Sprintf("libauth: user %q lacks role %q (roles: %v)",
			e.UserID, e.RequiredRole, e.Roles)
	case e.RequiredAny != nil:
		return fmt.Sprintf("libauth: user %q lacks all of %v (roles: %v)",
			e.UserID, e.RequiredAny, e.Roles)
	default:
		return fmt.Sprintf("libauth: user %q lacks permission %q (roles: %v)",
			e.UserID, e.Required.String(), e.Roles)
	}
}

func (e *PermissionDeniedError) Unwrap() error { return ErrPermissionDenied }
