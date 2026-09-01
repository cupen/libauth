package authz

import (
	"sort"

	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// RolesFor returns the user's effective role chain (direct roles plus
// their single-parent ancestors, deduplicated, sorted).
func (e *Enforcer) RolesFor(id model.UserID) ([]model.RoleID, error) {
	u, err := e.store.GetUser(id)
	if err != nil {
		return nil, err
	}
	return e.resolveRoles(u)
}

func (e *Enforcer) resolveRoles(u *model.User) ([]model.RoleID, error) {
	seen := make(map[model.RoleID]bool, len(u.Roles))
	queue := make([]model.RoleID, 0, 2*len(u.Roles))
	for _, r := range u.Roles {
		if !seen[r] {
			seen[r] = true
			queue = append(queue, r)
		}
	}

	// Walk up the single-parent chain. Termination is guaranteed: an
	// empty Parent ends a chain, and `seen` breaks cycles.
	for i := 0; i < len(queue); i++ {
		role, err := e.store.GetRole(queue[i])
		if err != nil {
			if err == store.ErrRoleNotFound {
				continue
			}
			return nil, err
		}
		if role.Parent != "" && !seen[role.Parent] {
			seen[role.Parent] = true
			queue = append(queue, role.Parent)
		}
	}

	sort.Slice(queue, func(i, j int) bool { return queue[i] < queue[j] })
	return queue, nil
}