package authz

import (
	"sort"

	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// RolesFor returns the user's effective role chain (direct + inherited,
// deduplicated, sorted).
func (e *Enforcer) RolesFor(id model.UserID) ([]model.RoleName, error) {
	u, err := e.store.GetUser(id)
	if err != nil {
		return nil, err
	}
	return e.resolveRoles(u)
}

func (e *Enforcer) resolveRoles(u *model.User) ([]model.RoleName, error) {
	seen := make(map[model.RoleName]bool, len(u.Roles))
	queue := make([]model.RoleName, 0, len(u.Roles))
	for _, r := range u.Roles {
		if !seen[r] {
			seen[r] = true
			queue = append(queue, r)
		}
	}

	// BFS expansion; each "round" walks the parents of one generation.
	// A round that appends no new roles ends the walk.
	processed := 0
	for depth := 1; processed < len(queue); depth++ {
		if depth > e.maxDepth {
			return nil, ErrInheritanceDepth
		}
		end := len(queue)
		for i := processed; i < end; i++ {
			role, err := e.store.GetRole(queue[i])
			if err != nil {
				if err == store.ErrRoleNotFound {
					continue
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
		if len(queue) == end {
			break // no new parents appended
		}
		processed = end
	}

	sort.Slice(queue, func(i, j int) bool { return queue[i] < queue[j] })
	return queue, nil
}
