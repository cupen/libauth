package libauth

import (
	"sort"
	"sync"
)

// MemoryStore is a thread-safe in-memory Store implementation, suitable for
// tests, demos and small services. All lookup results are copies, so callers
// cannot corrupt internal state by mutating returned values.
type MemoryStore struct {
	mu    sync.RWMutex
	users map[UserID]*User
	roles map[RoleName]*Role
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users: make(map[UserID]*User),
		roles: make(map[RoleName]*Role),
	}
}

func cloneUser(u *User) *User {
	c := &User{ID: u.ID}
	if len(u.Roles) > 0 {
		c.Roles = append([]RoleName(nil), u.Roles...)
	}
	if len(u.Direct) > 0 {
		c.Direct = append([]Permission(nil), u.Direct...)
	}
	return c
}

func cloneRole(r *Role) *Role {
	c := &Role{Name: r.Name}
	if len(r.Permissions) > 0 {
		c.Permissions = append([]Permission(nil), r.Permissions...)
	}
	if len(r.Parents) > 0 {
		c.Parents = append([]RoleName(nil), r.Parents...)
	}
	return c
}

// ---- users ----

// CreateUser stores a new user.
func (s *MemoryStore) CreateUser(u *User) error {
	if u == nil || u.ID == "" {
		return ErrEmptyName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; ok {
		return ErrUserExists
	}
	s.users[u.ID] = cloneUser(u)
	return nil
}

// GetUser returns a copy of the user.
func (s *MemoryStore) GetUser(id UserID) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	return cloneUser(u), nil
}

// DeleteUser removes the user.
func (s *MemoryStore) DeleteUser(id UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		return ErrUserNotFound
	}
	delete(s.users, id)
	return nil
}

// ListUsers returns copies of all users sorted by ID.
func (s *MemoryStore) ListUsers() ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, cloneUser(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ---- role assignment ----

// AssignRole adds a role to the user (idempotent).
func (s *MemoryStore) AssignRole(id UserID, role RoleName) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	for _, r := range u.Roles {
		if r == role {
			return nil
		}
	}
	u.Roles = append(u.Roles, role)
	return nil
}

// RevokeRole removes a role from the user (idempotent).
func (s *MemoryStore) RevokeRole(id UserID, role RoleName) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	kept := u.Roles[:0]
	for _, r := range u.Roles {
		if r != role {
			kept = append(kept, r)
		}
	}
	u.Roles = kept
	return nil
}

// ---- direct user permissions ----

// GrantUserPermission grants a permission directly to the user (idempotent).
func (s *MemoryStore) GrantUserPermission(id UserID, p Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	for _, g := range u.Direct {
		if g == p {
			return nil
		}
	}
	u.Direct = append(u.Direct, p)
	return nil
}

// RevokeUserPermission removes a direct permission from the user (idempotent).
func (s *MemoryStore) RevokeUserPermission(id UserID, p Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return ErrUserNotFound
	}
	kept := u.Direct[:0]
	for _, g := range u.Direct {
		if g != p {
			kept = append(kept, g)
		}
	}
	u.Direct = kept
	return nil
}

// ---- roles ----

// CreateRole inserts a new role.
func (s *MemoryStore) CreateRole(r *Role) error {
	if r == nil || r.Name == "" {
		return ErrEmptyName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[r.Name]; ok {
		return ErrRoleExists
	}
	s.roles[r.Name] = cloneRole(r)
	return nil
}

// UpdateRole replaces the definition of an existing role.
func (s *MemoryStore) UpdateRole(r *Role) error {
	if r == nil || r.Name == "" {
		return ErrEmptyName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[r.Name]; !ok {
		return ErrRoleNotFound
	}
	s.roles[r.Name] = cloneRole(r)
	return nil
}

// GetRole returns a copy of the role.
func (s *MemoryStore) GetRole(name RoleName) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[name]
	if !ok {
		return nil, ErrRoleNotFound
	}
	return cloneRole(r), nil
}

// DeleteRole removes the role.
func (s *MemoryStore) DeleteRole(name RoleName) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[name]; !ok {
		return ErrRoleNotFound
	}
	delete(s.roles, name)
	// Detach the deleted role from users and from child roles.
	for _, u := range s.users {
		kept := u.Roles[:0]
		for _, r := range u.Roles {
			if r != name {
				kept = append(kept, r)
			}
		}
		u.Roles = kept
	}
	for _, r := range s.roles {
		kept := r.Parents[:0]
		for _, p := range r.Parents {
			if p != name {
				kept = append(kept, p)
			}
		}
		r.Parents = kept
	}
	return nil
}

// ListRoles returns copies of all roles sorted by name.
func (s *MemoryStore) ListRoles() ([]*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Role, 0, len(s.roles))
	for _, r := range s.roles {
		out = append(out, cloneRole(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ---- role permissions ----

// GrantPermission adds a permission to the role (idempotent).
func (s *MemoryStore) GrantPermission(role RoleName, p Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[role]
	if !ok {
		return ErrRoleNotFound
	}
	for _, g := range r.Permissions {
		if g == p {
			return nil
		}
	}
	r.Permissions = append(r.Permissions, p)
	return nil
}

// RevokePermission removes a permission from the role (idempotent).
func (s *MemoryStore) RevokePermission(role RoleName, p Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[role]
	if !ok {
		return ErrRoleNotFound
	}
	kept := r.Permissions[:0]
	for _, g := range r.Permissions {
		if g != p {
			kept = append(kept, g)
		}
	}
	r.Permissions = kept
	return nil
}
