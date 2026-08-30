package authz

import (
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

func (e *Enforcer) CreateRole(name model.RoleName, permissions []model.Permission, parents ...model.RoleName) error {
	if name == "" {
		return store.ErrEmptyName
	}
	for _, p := range permissions {
		if !p.Valid() {
			return model.ErrInvalidPermission
		}
	}
	r := &model.Role{
		Name:        name,
		Permissions: append([]model.Permission(nil), permissions...),
		Parents:     append([]model.RoleName(nil), parents...),
	}
	if err := e.validateInheritance(r); err != nil {
		return err
	}
	// A brand-new role has no holders yet — cache needs no invalidation.
	return e.store.CreateRole(r)
}

func (e *Enforcer) UpdateRole(name model.RoleName, permissions []model.Permission, parents ...model.RoleName) error {
	if name == "" {
		return store.ErrEmptyName
	}
	for _, p := range permissions {
		if !p.Valid() {
			return model.ErrInvalidPermission
		}
	}
	r := &model.Role{
		Name:        name,
		Permissions: append([]model.Permission(nil), permissions...),
		Parents:     append([]model.RoleName(nil), parents...),
	}
	if err := e.validateInheritance(r); err != nil {
		return err
	}
	if err := e.store.UpdateRole(r); err != nil {
		return err
	}
	e.invalidateRoleHolders(name)
	return nil
}

// DeleteRole removes the role and cascade-detaches it from every user's
// Roles and every other role's Parents.
func (e *Enforcer) DeleteRole(name model.RoleName) error {
	if _, err := e.store.GetRole(name); err != nil {
		return err
	}
	// Use the holders index to scope the cascade-detach to users that
	// actually held the role, instead of scanning every user.
	e.cacheMu.RLock()
	holders := make([]model.UserID, 0, len(e.roleHolders[name]))
	for uid := range e.roleHolders[name] {
		holders = append(holders, uid)
	}
	e.cacheMu.RUnlock()

	for _, uid := range holders {
		u, err := e.store.GetUser(uid)
		if err != nil {
			return err
		}
		kept := u.Roles[:0]
		for _, r := range u.Roles {
			if r != name {
				kept = append(kept, r)
			}
		}
		if len(kept) != len(u.Roles) {
			u.Roles = kept
			if err := e.store.UpdateUser(u); err != nil {
				return err
			}
		}
		e.revokeHolder(uid, name)
	}

	roles, err := e.store.ListRoles()
	if err != nil {
		return err
	}
	for _, r := range roles {
		kept := r.Parents[:0]
		for _, p := range r.Parents {
			if p != name {
				kept = append(kept, p)
			}
		}
		if len(kept) != len(r.Parents) {
			r.Parents = kept
			if err := e.store.UpdateRole(r); err != nil {
				return err
			}
			e.invalidateRoleHolders(r.Name)
		}
	}

	// Drop any holders still listed for the deleted role and the per-user
	// caches that were about to be re-derived anyway.
	e.cacheMu.Lock()
	delete(e.roleHolders, name)
	e.cacheMu.Unlock()
	for _, uid := range holders {
		e.invalidateUser(uid)
	}
	return e.store.DeleteRole(name)
}

func (e *Enforcer) GetRole(name model.RoleName) (*model.Role, error) { return e.store.GetRole(name) }

func (e *Enforcer) ListRoles() ([]*model.Role, error) { return e.store.ListRoles() }

func (e *Enforcer) GrantPermission(role model.RoleName, p model.Permission) error {
	if !p.Valid() {
		return model.ErrInvalidPermission
	}
	r, err := e.store.GetRole(role)
	if err != nil {
		return err
	}
	for _, g := range r.Permissions {
		if g == p {
			return nil
		}
	}
	r.Permissions = append(r.Permissions, p)
	if err := e.store.UpdateRole(r); err != nil {
		return err
	}
	e.invalidateRoleHolders(role)
	return nil
}

func (e *Enforcer) RevokePermission(role model.RoleName, p model.Permission) error {
	if !p.Valid() {
		return model.ErrInvalidPermission
	}
	r, err := e.store.GetRole(role)
	if err != nil {
		return err
	}
	kept := r.Permissions[:0]
	for _, g := range r.Permissions {
		if g != p {
			kept = append(kept, g)
		}
	}
	r.Permissions = kept
	if err := e.store.UpdateRole(r); err != nil {
		return err
	}
	e.invalidateRoleHolders(role)
	return nil
}

func (e *Enforcer) AddParent(role, parent model.RoleName) error {
	r, err := e.store.GetRole(role)
	if err != nil {
		return err
	}
	if _, err := e.store.GetRole(parent); err != nil {
		return err
	}
	if r.HasParent(parent) {
		return nil
	}
	r.Parents = append(r.Parents, parent)
	if err := e.validateInheritance(r); err != nil {
		return err
	}
	if err := e.store.UpdateRole(r); err != nil {
		return err
	}
	e.invalidateRoleHolders(role)
	return nil
}
