package authz

import (
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

func (e *Enforcer) CreateUser(id model.UserID, roles ...model.RoleID) error {
	if id == "" {
		return store.ErrEmptyName
	}
	if err := e.store.CreateUser(&model.User{ID: id, Roles: append([]model.RoleID(nil), roles...)}); err != nil {
		return err
	}
	for _, role := range roles {
		e.grantHolder(id, role)
	}
	e.setDirectRoles(id, roles)
	return nil
}

// DeleteUser evicts cache and holders eagerly so observers stay consistent
// even if DeleteUser fails.
func (e *Enforcer) DeleteUser(id model.UserID) error {
	e.cacheMu.Lock()
	delete(e.cache, id)
	delete(e.directRoles, id)
	for _, holders := range e.roleHolders {
		delete(holders, id)
	}
	e.cacheMu.Unlock()

	return e.store.DeleteUser(id)
}

func (e *Enforcer) GetUser(id model.UserID) (*model.User, error) { return e.store.GetUser(id) }
func (e *Enforcer) ListUsers() ([]*model.User, error)             { return e.store.ListUsers() }

func (e *Enforcer) AssignRole(id model.UserID, role model.RoleID) error {
	if _, err := e.store.GetRole(role); err != nil {
		return err
	}
	u, err := e.store.GetUser(id)
	if err != nil {
		return err
	}
	for _, r := range u.Roles {
		if r == role {
			return nil
		}
	}
	u.Roles = append(u.Roles, role)
	if err := e.store.UpdateUser(u); err != nil {
		return err
	}
	e.grantHolder(id, role)
	e.setDirectRoles(id, u.Roles)
	e.invalidateUser(id)
	return nil
}

func (e *Enforcer) RevokeRole(id model.UserID, role model.RoleID) error {
	u, err := e.store.GetUser(id)
	if err != nil {
		return err
	}
	if _, err := e.store.GetRole(role); err != nil {
		return err
	}
	kept := u.Roles[:0]
	for _, r := range u.Roles {
		if r != role {
			kept = append(kept, r)
		}
	}
	u.Roles = kept
	if err := e.store.UpdateUser(u); err != nil {
		return err
	}
	e.revokeHolder(id, role)
	e.setDirectRoles(id, u.Roles)
	e.invalidateUser(id)
	return nil
}

func (e *Enforcer) GrantDirectPermission(id model.UserID, p model.Permission) error {
	if !p.Valid() {
		return model.ErrInvalidPermission
	}
	u, err := e.store.GetUser(id)
	if err != nil {
		return err
	}
	for _, g := range u.Direct {
		if g == p {
			return nil
		}
	}
	u.Direct = append(u.Direct, p)
	if err := e.store.UpdateUser(u); err != nil {
		return err
	}
	e.invalidateUser(id)
	return nil
}

func (e *Enforcer) RevokeDirectPermission(id model.UserID, p model.Permission) error {
	if !p.Valid() {
		return model.ErrInvalidPermission
	}
	u, err := e.store.GetUser(id)
	if err != nil {
		return err
	}
	kept := u.Direct[:0]
	for _, g := range u.Direct {
		if g != p {
			kept = append(kept, g)
		}
	}
	u.Direct = kept
	if err := e.store.UpdateUser(u); err != nil {
		return err
	}
	e.invalidateUser(id)
	return nil
}