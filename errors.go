package libauth

import (
	"github.com/cupen/libauth/authz"
	"github.com/cupen/libauth/jwt"
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

	ErrTokenMalformed      = jwt.ErrTokenMalformed
	ErrTokenBadSignature   = jwt.ErrTokenBadSignature
	ErrTokenExpired        = jwt.ErrTokenExpired
	ErrTokenNotYetValid    = jwt.ErrTokenNotYetValid
	ErrTokenIssuedInFuture = jwt.ErrTokenIssuedInFuture
	ErrAlgMismatch         = jwt.ErrAlgMismatch
	ErrUnexpectedTyp       = jwt.ErrUnexpectedTyp
	ErrUnsupportedCrit     = jwt.ErrUnsupportedCrit
	ErrMissingExpiration   = jwt.ErrMissingExpiration
	ErrReservedClaim       = jwt.ErrReservedClaim
	ErrIssuerMismatch      = jwt.ErrIssuerMismatch
	ErrAudienceMismatch    = jwt.ErrAudienceMismatch
	ErrInvalidKey          = jwt.ErrInvalidKey
)

type PermissionDeniedError = model.PermissionDeniedError
