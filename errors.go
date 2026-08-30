package libauth

import (
	"github.com/cupen/libauth/authz"
	"github.com/cupen/libauth/middleware"
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

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

	ErrInvalidIdentityFunc = middleware.ErrInvalidIdentityFunc
)

type PermissionDeniedError = model.PermissionDeniedError
