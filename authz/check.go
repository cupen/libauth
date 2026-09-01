package authz

import (
	"sort"

	"github.com/cupen/libauth/model"
)

// HasRole reports whether the user holds the role directly (inheritance
// is not followed — see RolesFor for the effective chain).
func (e *Enforcer) HasRole(id model.UserID, role model.RoleID) (bool, error) {
	set, err := e.directRolesOf(id)
	if err != nil {
		return false, err
	}
	_, ok := set[role]
	return ok, nil
}

// HasAnyRole reports whether the user holds any of the roles directly.
func (e *Enforcer) HasAnyRole(id model.UserID, roles ...model.RoleID) (bool, error) {
	if len(roles) == 0 {
		return false, nil
	}
	set, err := e.directRolesOf(id)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if _, ok := set[role]; ok {
			return true, nil
		}
	}
	return false, nil
}

// HasAllRoles reports whether the user holds every listed role directly.
// The empty list is vacuously true.
func (e *Enforcer) HasAllRoles(id model.UserID, roles ...model.RoleID) (bool, error) {
	if len(roles) == 0 {
		return true, nil
	}
	set, err := e.directRolesOf(id)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if _, ok := set[role]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func (e *Enforcer) HasPermission(id model.UserID, required model.Permission) (bool, error) {
	set, err := e.getGrantedSet(id)
	if err != nil {
		return false, err
	}
	return set.has(required), nil
}

// Check returns nil when access is granted. On denial it returns a
// *model.PermissionDeniedError matchable via errors.Is with
// model.ErrPermissionDenied.
func (e *Enforcer) Check(id model.UserID, required model.Permission) error {
	set, u, roles, err := e.getGrantedSetFull(id)
	if err != nil {
		return err
	}
	if set.has(required) {
		return nil
	}
	return &model.PermissionDeniedError{
		UserID:   id,
		User:     u,
		Required: required,
		Roles:    roles,
	}
}

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

// PermissionsFor returns every permission the user effectively holds,
// sorted for deterministic output.
func (e *Enforcer) PermissionsFor(id model.UserID) ([]model.Permission, error) {
	set, err := e.getGrantedSet(id)
	if err != nil {
		return nil, err
	}
	out := set.flatten()
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}