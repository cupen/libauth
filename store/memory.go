package store

import (
	"slices"
	"sync"

	"github.com/cupen/libauth/model"
)

// MemoryStore is a thread-safe in-memory Store.
type MemoryStore struct {
	mu    sync.RWMutex
	users map[model.UserID]*model.User
	roles map[model.RoleID]*model.Role
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users: make(map[model.UserID]*model.User),
		roles: make(map[model.RoleID]*model.Role),
	}
}

func cloneUser(u *model.User) *model.User {
	c := &model.User{ID: u.ID}
	if len(u.Roles) > 0 {
		c.Roles = slices.Clone(u.Roles)
	}
	if len(u.Direct) > 0 {
		c.Direct = slices.Clone(u.Direct)
	}
	return c
}

func cloneRole(r *model.Role) *model.Role {
	c := &model.Role{Name: r.Name, Parent: r.Parent}
	if len(r.Permissions) > 0 {
		c.Permissions = slices.Clone(r.Permissions)
	}
	return c
}
