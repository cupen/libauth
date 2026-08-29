package libauth

import (
	"sort"
)

// DefaultMaxDepth bounds role-inheritance resolution to protect against
// pathological graphs (cycles are rejected earlier at write time).
const DefaultMaxDepth = 32

// Manager is the high-level RBAC API. It wraps a Store and adds validation,
// role-inheritance resolution and permission checks.
//
// A Manager is safe for concurrent use as long as the underlying Store is.
type Manager struct {
	store    Store
	maxDepth int
}

// Option configures a Manager.
type Option func(*Manager)

// WithStore replaces the backing store (defaults to a MemoryStore).
func WithStore(s Store) Option {
	return func(m *Manager) { m.store = s }
}

// WithMaxDepth overrides the maximum role-inheritance depth.
func WithMaxDepth(n int) Option {
	return func(m *Manager) {
		if n > 0 {
			m.maxDepth = n
		}
	}
}

// New creates a Manager backed by an in-memory store by default.
func New(opts ...Option) *Manager {
	m := &Manager{
		store:    NewMemoryStore(),
		maxDepth: DefaultMaxDepth,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Store exposes the backing store (read-only usage encouraged).
func (m *Manager) Store() Store { return m.store }

// ---- users ----

// CreateUser registers a new user with the given roles.
func (m *Manager) CreateUser(id UserID, roles ...RoleName) error {
	if id == "" {
		return ErrEmptyName
	}
	return m.store.CreateUser(&User{ID: id, Roles: append([]RoleName(nil), roles...)})
}

// DeleteUser removes the user.
func (m *Manager) DeleteUser(id UserID) error { return m.store.DeleteUser(id) }

// GetUser returns a copy of the user.
func (m *Manager) GetUser(id UserID) (*User, error) { return m.store.GetUser(id) }

// ListUsers returns all users.
func (m *Manager) ListUsers() ([]*User, error) { return m.store.ListUsers() }

// AssignRole grants a role to the user. The role must exist.
func (m *Manager) AssignRole(id UserID, role RoleName) error {
	if _, err := m.store.GetRole(role); err != nil {
		return err
	}
	return m.store.AssignRole(id, role)
}

// RevokeRole removes a role from the user.
func (m *Manager) RevokeRole(id UserID, role RoleName) error {
	return m.store.RevokeRole(id, role)
}

// GrantDirectPermission grants a permission to the user directly, bypassing
// roles. The permission must be well-formed.
func (m *Manager) GrantDirectPermission(id UserID, p Permission) error {
	if !p.Valid() {
		return ErrInvalidPermission
	}
	return m.store.GrantUserPermission(id, p)
}

// RevokeDirectPermission removes a direct permission from the user.
func (m *Manager) RevokeDirectPermission(id UserID, p Permission) error {
	return m.store.RevokeUserPermission(id, p)
}

// ---- roles ----

// CreateRole registers a new role. Parents must exist and must not create a
// cycle.
func (m *Manager) CreateRole(name RoleName, permissions []Permission, parents ...RoleName) error {
	if name == "" {
		return ErrEmptyName
	}
	for _, p := range permissions {
		if !p.Valid() {
			return ErrInvalidPermission
		}
	}
	r := &Role{
		Name:        name,
		Permissions: append([]Permission(nil), permissions...),
		Parents:     append([]RoleName(nil), parents...),
	}
	if err := m.validateInheritance(r); err != nil {
		return err
	}
	return m.store.CreateRole(r)
}

// UpdateRole replaces a role's permissions and parents. Cycles are rejected.
func (m *Manager) UpdateRole(name RoleName, permissions []Permission, parents ...RoleName) error {
	if name == "" {
		return ErrEmptyName
	}
	for _, p := range permissions {
		if !p.Valid() {
			return ErrInvalidPermission
		}
	}
	r := &Role{
		Name:        name,
		Permissions: append([]Permission(nil), permissions...),
		Parents:     append([]RoleName(nil), parents...),
	}
	if err := m.validateInheritance(r); err != nil {
		return err
	}
	return m.store.UpdateRole(r)
}

// DeleteRole removes the role and detaches it from users and child roles.
func (m *Manager) DeleteRole(name RoleName) error { return m.store.DeleteRole(name) }

// GetRole returns a copy of the role.
func (m *Manager) GetRole(name RoleName) (*Role, error) { return m.store.GetRole(name) }

// ListRoles returns all roles.
func (m *Manager) ListRoles() ([]*Role, error) { return m.store.ListRoles() }

// GrantPermission adds a permission to a role.
func (m *Manager) GrantPermission(role RoleName, p Permission) error {
	if !p.Valid() {
		return ErrInvalidPermission
	}
	return m.store.GrantPermission(role, p)
}

// RevokePermission removes a permission from a role.
func (m *Manager) RevokePermission(role RoleName, p Permission) error {
	return m.store.RevokePermission(role, p)
}

// AddParent makes a role inherit from a parent role. Cycles are rejected.
func (m *Manager) AddParent(role, parent RoleName) error {
	r, err := m.store.GetRole(role)
	if err != nil {
		return err
	}
	if _, err := m.store.GetRole(parent); err != nil {
		return err
	}
	if r.HasParent(parent) {
		return nil
	}
	r.Parents = append(r.Parents, parent)
	if err := m.validateInheritance(r); err != nil {
		return err
	}
	return m.store.UpdateRole(r)
}

// ---- resolution ----

// RolesFor returns the user's effective role chain: directly assigned roles
// plus all roles inherited transitively through parents, deduplicated and
// sorted for deterministic output.
func (m *Manager) RolesFor(id UserID) ([]RoleName, error) {
	u, err := m.store.GetUser(id)
	if err != nil {
		return nil, err
	}
	roles, err := m.resolveRoles(u)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

// resolveRoles walks the role graph breadth-first from the user's direct
// roles, guarding depth and revisits.
func (m *Manager) resolveRoles(u *User) ([]RoleName, error) {
	seen := make(map[RoleName]bool, len(u.Roles))
	queue := make([]RoleName, 0, len(u.Roles))
	for _, r := range u.Roles {
		if !seen[r] {
			seen[r] = true
			queue = append(queue, r)
		}
	}

	depth := 0
	for i := 0; i < len(queue); i++ {
		if depth++; depth > m.maxDepth {
			return nil, ErrInheritanceDepth
		}
		role, err := m.store.GetRole(queue[i])
		if err != nil {
			if err == ErrRoleNotFound {
				continue // dangling reference: ignore rather than fail closed
			}
			return nil, err
		}
		for _, parent := range role.Parents {
			if !seen[parent] {
				seen[parent] = true
				queue = append(queue, parent)
			}
		}
	}

	sort.Slice(queue, func(i, j int) bool { return queue[i] < queue[j] })
	return queue, nil
}

// PermissionsFor returns every permission effective for the user: the union
// of all (inherited) role permissions plus the user's direct permissions,
// deduplicated and sorted for deterministic output.
func (m *Manager) PermissionsFor(id UserID) ([]Permission, error) {
	u, err := m.store.GetUser(id)
	if err != nil {
		return nil, err
	}
	return m.effectivePermissions(u)
}

func (m *Manager) effectivePermissions(u *User) ([]Permission, error) {
	roles, err := m.resolveRoles(u)
	if err != nil {
		return nil, err
	}
	set := make(map[Permission]bool)
	for _, name := range roles {
		role, err := m.store.GetRole(name)
		if err != nil {
			if err == ErrRoleNotFound {
				continue
			}
			return nil, err
		}
		for _, p := range role.Permissions {
			set[p] = true
		}
	}
	for _, p := range u.Direct {
		set[p] = true
	}
	out := make([]Permission, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// ---- checks ----

// HasRole reports whether the user holds the role directly.
func (m *Manager) HasRole(id UserID, role RoleName) (bool, error) {
	u, err := m.store.GetUser(id)
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
func (m *Manager) HasAnyRole(id UserID, roles ...RoleName) (bool, error) {
	for _, role := range roles {
		ok, err := m.HasRole(id, role)
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
func (m *Manager) HasAllRoles(id UserID, roles ...RoleName) (bool, error) {
	for _, role := range roles {
		ok, err := m.HasRole(id, role)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// HasPermission reports whether any of the user's effective roles grants the
// permission, or the user holds it directly.
func (m *Manager) HasPermission(id UserID, required Permission) (bool, error) {
	u, err := m.store.GetUser(id)
	if err != nil {
		return false, err
	}
	return m.check(u, required)
}

func (m *Manager) check(u *User, required Permission) (bool, error) {
	roles, err := m.resolveRoles(u)
	if err != nil {
		return false, err
	}
	for _, name := range roles {
		role, err := m.store.GetRole(name)
		if err != nil {
			if err == ErrRoleNotFound {
				continue
			}
			return false, err
		}
		if role.HasPermission(required) {
			return true, nil
		}
	}
	for _, p := range u.Direct {
		if p.Matches(required) {
			return true, nil
		}
	}
	return false, nil
}

// Check is the error-returning flavor of HasPermission. It returns
// *PermissionDeniedError (matchable via errors.Is with ErrPermissionDenied)
// when access must be denied, ErrUserNotFound when the user does not exist,
// and nil when access is granted.
func (m *Manager) Check(id UserID, required Permission) error {
	u, err := m.store.GetUser(id)
	if err != nil {
		return err
	}
	ok, err := m.check(u, required)
	if err != nil {
		return err
	}
	if !ok {
		roles, rerr := m.resolveRoles(u)
		if rerr != nil {
			roles = u.Roles
		}
		return &PermissionDeniedError{
			UserID:   u.ID,
			User:     u,
			Required: required,
			Roles:    roles,
		}
	}
	return nil
}

// HasAllPermissions reports whether every listed permission is granted.
func (m *Manager) HasAllPermissions(id UserID, required ...Permission) (bool, error) {
	for _, p := range required {
		ok, err := m.HasPermission(id, p)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// HasAnyPermission reports whether at least one listed permission is granted.
func (m *Manager) HasAnyPermission(id UserID, required ...Permission) (bool, error) {
	for _, p := range required {
		ok, err := m.HasPermission(id, p)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// ---- validation ----

// validateInheritance ensures every parent exists and that enabling the role
// does not create an inheritance cycle reachable from itself.
func (m *Manager) validateInheritance(r *Role) error {
	for _, parent := range r.Parents {
		if parent == r.Name {
			return ErrCyclicInheritance
		}
		if _, err := m.store.GetRole(parent); err != nil {
			return err
		}
	}

	// Walk ancestors from r; if we can reach r again, the graph is cyclic.
	visited := map[RoleName]bool{r.Name: true}
	queue := append([]RoleName(nil), r.Parents...)
	for depth := 0; len(queue) > 0; depth++ {
		if depth > m.maxDepth {
			return ErrInheritanceDepth
		}
		next := make([]RoleName, 0, len(queue))
		for _, name := range queue {
			if name == r.Name {
				return ErrCyclicInheritance
			}
			if visited[name] {
				continue
			}
			visited[name] = true
			role, err := m.store.GetRole(name)
			if err != nil {
				if err == ErrRoleNotFound {
					continue
				}
				return err
			}
			next = append(next, role.Parents...)
		}
		queue = next
	}
	return nil
}
