package libauth

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the manager and stores.
var (
	ErrUserNotFound        = errors.New("libauth: user not found")
	ErrRoleNotFound        = errors.New("libauth: role not found")
	ErrUserExists          = errors.New("libauth: user already exists")
	ErrRoleExists          = errors.New("libauth: role already exists")
	ErrEmptyName           = errors.New("libauth: empty name")
	ErrCyclicInheritance   = errors.New("libauth: cyclic role inheritance")
	ErrPermissionDenied    = errors.New("libauth: permission denied")
	ErrInheritanceDepth    = errors.New("libauth: role inheritance too deep")
	ErrInvalidPermission   = errors.New("libauth: invalid permission")
	ErrInvalidIdentityFunc = errors.New("libauth: identity func is required")
)

// PermissionDeniedError carries the details of a failed authorization check.
type PermissionDeniedError struct {
	UserID   UserID
	User     *User
	Required Permission
	// Roles lists the user's effective role chain at check time.
	Roles []RoleName
}

func (e *PermissionDeniedError) Error() string {
	return fmt.Sprintf("libauth: user %q lacks permission %q (roles: %v)",
		e.UserID, e.Required, e.Roles)
}

// Unwrap allows errors.Is(err, ErrPermissionDenied) to match.
func (e *PermissionDeniedError) Unwrap() error { return ErrPermissionDenied }
