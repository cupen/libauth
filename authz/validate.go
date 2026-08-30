package authz

import (
	"github.com/cupen/libauth/model"
	"github.com/cupen/libauth/store"
)

// validateInheritance rejects self-parents, cycles and chains deeper than
// maxDepth. With single parents the ancestor walk is a simple loop.
func (e *Enforcer) validateInheritance(r *model.Role) error {
	if r.Parent == "" {
		return nil
	}
	if r.Parent == r.Name {
		return ErrCyclicInheritance
	}
	if _, err := e.store.GetRole(r.Parent); err != nil {
		return err
	}

	// Walk up from r.Parent; reaching r again closes a cycle.
	name := r.Parent
	for depth := 1; name != ""; depth++ {
		if name == r.Name {
			return ErrCyclicInheritance
		}
		if depth > e.maxDepth {
			return ErrInheritanceDepth
		}
		role, err := e.store.GetRole(name)
		if err != nil {
			if err == store.ErrRoleNotFound {
				break // dangling ancestor: tolerated, can only come from external store edits
			}
			return err
		}
		name = role.Parent
	}
	return nil
}
