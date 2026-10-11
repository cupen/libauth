package store

import (
	"sort"

	"github.com/cupen/libauth/model"
)

func (s *MemoryStore) CreateUser(u *model.User) error {
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

func (s *MemoryStore) UpdateUser(u *model.User) error {
	if u == nil || u.ID == "" {
		return ErrEmptyName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.ID]; !ok {
		return ErrUserNotFound
	}
	s.users[u.ID] = cloneUser(u)
	return nil
}

func (s *MemoryStore) GetUser(id model.UserID) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	return cloneUser(u), nil
}

func (s *MemoryStore) DeleteUser(id model.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[id]; !ok {
		return ErrUserNotFound
	}
	delete(s.users, id)
	return nil
}

func (s *MemoryStore) ListUsers() ([]*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, cloneUser(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
