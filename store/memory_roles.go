package store

import (
	"sort"

	"github.com/cupen/libauth/model"
)

func (s *MemoryStore) CreateRole(r *model.Role) error {
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

func (s *MemoryStore) UpdateRole(r *model.Role) error {
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

func (s *MemoryStore) GetRole(name model.RoleName) (*model.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[name]
	if !ok {
		return nil, ErrRoleNotFound
	}
	return cloneRole(r), nil
}

// DeleteRole does not cascade-detach the role from users or from other
// roles' parent lists — that bookkeeping is the caller's job.
func (s *MemoryStore) DeleteRole(name model.RoleName) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[name]; !ok {
		return ErrRoleNotFound
	}
	delete(s.roles, name)
	return nil
}

func (s *MemoryStore) ListRoles() ([]*model.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Role, 0, len(s.roles))
	for _, r := range s.roles {
		out = append(out, cloneRole(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
