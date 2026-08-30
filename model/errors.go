package model

import (
	"errors"
	"fmt"
)

var (
	ErrPermissionDenied  = errors.New("libauth: permission denied")
	ErrInvalidPermission = errors.New("libauth: invalid permission")
)

// PermissionDeniedError carries the details of a failed authorization check.
type PermissionDeniedError struct {
	UserID   UserID
	User     *User
	Required Permission
	Roles    []RoleName
}

func (e *PermissionDeniedError) Error() string {
	return fmt.Sprintf("libauth: user %q lacks permission %q (roles: %v)",
		e.UserID, e.Required.String(), e.Roles)
}

func (e *PermissionDeniedError) Unwrap() error { return ErrPermissionDenied }
