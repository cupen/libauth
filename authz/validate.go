package authz

import (
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

func (e *Enforcer) validateInheritance(r *model.Role) error {
	for _, parent := range r.Parents {
		if parent == r.Name {
			return ErrCyclicInheritance
		}
		if _, err := e.store.GetRole(parent); err != nil {
			return err
		}
	}

	visited := map[model.RoleName]bool{r.Name: true}
	queue := append([]model.RoleName(nil), r.Parents...)
	for depth := 0; len(queue) > 0; depth++ {
		if depth > e.maxDepth {
			return ErrInheritanceDepth
		}
		next := make([]model.RoleName, 0, len(queue))
		for _, name := range queue {
			if name == r.Name {
				return ErrCyclicInheritance
			}
			if visited[name] {
				continue
			}
			visited[name] = true
			role, err := e.store.GetRole(name)
			if err != nil {
				if err == store.ErrRoleNotFound {
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
