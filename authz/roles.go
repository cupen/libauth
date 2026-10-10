package authz

import (
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// CreateRole registers a new role. Parent, when non-empty, must exist and
// must not create a cycle or exceed the inheritance depth cap.
func (e *Enforcer) CreateRole(name model.RoleID, permissions []model.Permission, parent model.RoleID) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
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
		Parent:      parent,
	}
	if err := e.validateInheritance(r); err != nil {
		return err
	}
	return e.store.CreateRole(r)
}

// UpdateRole replaces a role's permissions and parent.
func (e *Enforcer) UpdateRole(name model.RoleID, permissions []model.Permission, parent model.RoleID) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
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
		Parent:      parent,
	}
	if err := e.validateInheritance(r); err != nil {
		return err
	}
	if err := e.store.UpdateRole(r); err != nil {
		return err
	}
	e.invalidateRole(name)
	return nil
}

// DeleteRole removes the role and cascade-detaches it from every user's
// Roles and from every role that named it as Parent.
func (e *Enforcer) DeleteRole(name model.RoleID) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	if _, err := e.store.GetRole(name); err != nil {
		return err
	}
	// Scope the cascade-detach to users that actually held the role.
	e.cacheMu.RLock()
	holders := make([]model.UserID, 0, len(e.roleHolders[name]))
	for uid := range e.roleHolders[name] {
		holders = append(holders, uid)
	}
	e.cacheMu.RUnlock()
	detachedUsers := make([]*model.User, 0, len(holders))

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
		detachedUsers = append(detachedUsers, u)
	}

	roles, err := e.store.ListRoles()
	if err != nil {
		return err
	}
	// Subtree of the deleted role, computed from the pre-deletion graph:
	// every descendant stops inheriting through it once it is gone.
	detached := make([]model.RoleID, 0, len(roles))
	for _, r := range roles {
		if r.Parent == name {
			r.Parent = ""
			if err := e.store.UpdateRole(r); err != nil {
				return err
			}
			detached = append(detached, r.Name)
		}
	}

	if err := e.store.DeleteRole(name); err != nil {
		return err
	}
	// Invalidate holders of the deleted role and of every role whose
	// inheritance chain passed through it — their effective permission
	// sets all changed. Only the deleted role's reverse-index entry goes;
	// detached descendants still exist and keep their holders.
	e.commit(func() {
		drop := map[model.RoleID]struct{}{name: {}}
		for _, r := range detached {
			drop[r] = struct{}{}
		}
		// Detached roles lost a link: roles that inherited through them
		// must be invalidated too.
		for _, r := range roles {
			if _, ok := drop[r.Parent]; ok {
				drop[r.Name] = struct{}{}
			}
		}
		for role := range drop {
			for uid := range e.roleHolders[role] {
				delete(e.cache, uid)
			}
		}
		delete(e.roleHolders, name)
		for _, u := range detachedUsers {
			set := make(map[model.RoleID]struct{}, len(u.Roles))
			for _, r := range u.Roles {
				set[r] = struct{}{}
			}
			e.directRoles[u.ID] = set
		}
	})
	return nil
}

func (e *Enforcer) GetRole(name model.RoleID) (*model.Role, error) { return e.store.GetRole(name) }
func (e *Enforcer) ListRoles() ([]*model.Role, error)              { return e.store.ListRoles() }

func (e *Enforcer) GrantPermission(role model.RoleID, p model.Permission) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
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
	e.invalidateRole(role)
	return nil
}

func (e *Enforcer) RevokePermission(role model.RoleID, p model.Permission) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
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
	e.invalidateRole(role)
	return nil
}

// SetParent makes role inherit from parent. A role has at most one parent;
// setting a new parent replaces the previous one, and an empty parent
// detaches the role from any inheritance chain.
func (e *Enforcer) SetParent(role, parent model.RoleID) error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	r, err := e.store.GetRole(role)
	if err != nil {
		return err
	}
	if _, err := e.store.GetRole(parent); parent != "" && err != nil {
		return err
	}
	if r.Parent == parent {
		return nil
	}
	r.Parent = parent
	if err := e.validateInheritance(r); err != nil {
		return err
	}
	if err := e.store.UpdateRole(r); err != nil {
		return err
	}
	e.invalidateRole(role)
	return nil
}
