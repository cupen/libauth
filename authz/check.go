package authz

import (
	"sort"

	"github.com/cupen/libauth/model"
)

// HasRole reports whether the user holds the role directly.
func (e *Enforcer) HasRole(id model.UserID, role model.RoleID) (bool, error) {
	u, err := e.store.GetUser(id)
	if err != nil {
		return false, err
	}
	for _, r := range u.Roles {
		if r == role {
			return true, nil
		}
	}
	return false, nil
}

// HasAnyRole reports whether the user holds any of the roles directly.
func (e *Enforcer) HasAnyRole(id model.UserID, roles ...model.RoleID) (bool, error) {
	for _, role := range roles {
		ok, err := e.HasRole(id, role)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// HasAllRoles reports whether the user holds every listed role directly.
func (e *Enforcer) HasAllRoles(id model.UserID, roles ...model.RoleID) (bool, error) {
	for _, role := range roles {
		ok, err := e.HasRole(id, role)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// HasPermission reports whether the user holds the permission (via any
// effective role or a direct grant).
func (e *Enforcer) HasPermission(id model.UserID, required model.Permission) (bool, error) {
	set, err := e.getGrantedSet(id)
	if err != nil {
		return false, err
	}
	return set.has(required), nil
}

// Check returns nil when access is granted. On denial it returns a
// *model.PermissionDeniedError (matchable via errors.Is with
// model.ErrPermissionDenied) carrying the user's effective roles.
func (e *Enforcer) Check(id model.UserID, required model.Permission) error {
	set, err := e.getGrantedSet(id)
	if err != nil {
		return err
	}
	if set.has(required) {
		return nil
	}
	// On denial, fetch the user for the error context (denied path is rare).
	u, err := e.store.GetUser(id)
	if err != nil {
		return err
	}
	roles, rerr := e.resolveRoles(u)
	if rerr != nil {
		roles = u.Roles
	}
	return &model.PermissionDeniedError{
		UserID:   id,
		User:     u,
		Required: required,
		Roles:    roles,
	}
}

// HasAllPermissions reports whether every listed permission is granted.
func (e *Enforcer) HasAllPermissions(id model.UserID, required ...model.Permission) (bool, error) {
	set, err := e.getGrantedSet(id)
	if err != nil {
		return false, err
	}
	for _, p := range required {
		if !set.has(p) {
			return false, nil
		}
	}
	return true, nil
}

// HasAnyPermission reports whether at least one listed permission is granted.
func (e *Enforcer) HasAnyPermission(id model.UserID, required ...model.Permission) (bool, error) {
	set, err := e.getGrantedSet(id)
	if err != nil {
		return false, err
	}
	for _, p := range required {
		if set.has(p) {
			return true, nil
		}
	}
	return false, nil
}

// PermissionsFor returns every permission the user effectively holds
// (inherited role permissions plus direct grants), sorted for deterministic
// output.
func (e *Enforcer) PermissionsFor(id model.UserID) ([]model.Permission, error) {
	set, err := e.getGrantedSet(id)
	if err != nil {
		return nil, err
	}
	out := set.flatten()
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}
