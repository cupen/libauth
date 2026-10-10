package libauth

import (
	"github.com/cupen/libauth/authz"
	"github.com/cupen/libauth/middleware"
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// Sentinel errors of the RBAC core, re-exported so callers can branch with
// errors.Is after importing only the root package. Token errors stay in
// their own jwt / branca packages — matching them means using those
// packages anyway.
var (
	ErrUserNotFound = store.ErrUserNotFound
	ErrRoleNotFound = store.ErrRoleNotFound
	ErrUserExists   = store.ErrUserExists
	ErrRoleExists   = store.ErrRoleExists
	ErrEmptyName    = store.ErrEmptyName

	ErrPermissionDenied  = model.ErrPermissionDenied
	ErrInvalidPermission = model.ErrInvalidPermission

	ErrCyclicInheritance = authz.ErrCyclicInheritance
	ErrInheritanceDepth  = authz.ErrInheritanceDepth

	ErrNilAuthorizer   = middleware.ErrNilAuthorizer
	ErrNilIdentityFunc = middleware.ErrNilIdentityFunc
)

type PermissionDeniedError = model.PermissionDeniedError
