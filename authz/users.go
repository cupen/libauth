package authz

import (
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

func (e *Enforcer) CreateUser(id model.UserID, roles ...model.RoleName) error {
	if id == "" {
		return store.ErrEmptyName
	}
	if err := e.store.CreateUser(&model.User{ID: id, Roles: append([]model.RoleName(nil), roles...)}); err != nil {
		return err
	}
	for _, role := range roles {
		e.grantHolder(id, role)
	}
	return nil
}

func (e *Enforcer) DeleteUser(id model.UserID) error {
	// Evict cache and holders eagerly; doing it before the store call keeps
	// observers consistent if DeleteUser fails.
	e.cacheMu.Lock()
	delete(e.cache, id)
	for _, holders := range e.roleHolders {
		delete(holders, id)
	}
	e.cacheMu.Unlock()

	return e.store.DeleteUser(id)
}

func (e *Enforcer) GetUser(id model.UserID) (*model.User, error) { return e.store.GetUser(id) }

func (e *Enforcer) ListUsers() ([]*model.User, error) { return e.store.ListUsers() }

func (e *Enforcer) AssignRole(id model.UserID, role model.RoleName) error {
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
	e.invalidateUser(id)
	return nil
}

func (e *Enforcer) RevokeRole(id model.UserID, role model.RoleName) error {
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
