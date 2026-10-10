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
//
// The allow path is the hot one: a warm check is a few map lookups and
// never touches the store. The store is read once more only to populate
// the denial error's context.
func (e *Enforcer) Check(id model.UserID, required model.Permission) error {
	set, err := e.getGrantedSet(id)
	if err != nil {
		return err
	}
	if set.has(required) {
		return nil
	}
	u, err := e.store.GetUser(id)
	if err != nil {
		return err
	}
	roles, err := e.resolveRoles(u)
	if err != nil {
		roles = u.Roles
	}
	return &model.PermissionDeniedError{
		UserID:   id,
		User:     u,
		Required: required,
		Roles:    roles,
	}
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
