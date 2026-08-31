package authz

import (
	"fmt"
	"testing"

	"github.com/cupen/libauth/model"
)

// buildEnforcer creates an Enforcer with resources × actions grants
// distributed across `resources` roles (one role per resource, each role
// grants `actions` permissions). One user "u" holds every role, so its
// effective granted set has resources × actions permissions.
func buildEnforcer(b *testing.B, resources, actions int) (*Enforcer, model.Permission) {
	b.Helper()
	e := New()
	const userID = model.UserID("u")

	for i := 0; i < resources; i++ {
		rname := model.RoleID(fmt.Sprintf("r%d", i))
		perms := make([]model.Permission, actions)
		for j := 0; j < actions; j++ {
			perms[j] = model.Permission{
				Resource: fmt.Sprintf("res%d", i),
				Action:   fmt.Sprintf("act%d", j),
			}
		}
		if err := e.CreateRole(rname, perms, ""); err != nil {
			b.Fatal(err)
		}
	}

	roleNames := make([]model.RoleID, resources)
	for i := 0; i < resources; i++ {
		roleNames[i] = model.RoleID(fmt.Sprintf("r%d", i))
	}
	if err := e.CreateUser(userID, roleNames...); err != nil {
		b.Fatal(err)
	}

	query := model.Permission{Resource: "res0", Action: "act0"}
	return e, query
}

// runScale drives one Check iteration at the given (resources, actions)
// scale. variant toggles between cache-hit (steady state) and cache-cold
// (forced miss each iteration).
func runScale(b *testing.B, resources, actions int, cold bool) {
	e, query := buildEnforcer(b, resources, actions)
	const uid = model.UserID("u")

	if !cold {
		// Prime cache.
		if err := e.Check(uid, query); err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if cold {
			e.invalidateUser(uid)
		}
		_ = e.Check(uid, query)
	}
}

// BenchmarkCheck_R100A10Hit — 100 resources × 10 actions = 1000 grants.
func BenchmarkCheck_R100A10Hit(b *testing.B)  { runScale(b, 100, 10, false) }
func BenchmarkCheck_R100A10Cold(b *testing.B) { runScale(b, 100, 10, true) }

// BenchmarkCheck_R100A100Hit — 100 resources × 100 actions = 10000 grants.
func BenchmarkCheck_R100A100Hit(b *testing.B)  { runScale(b, 100, 100, false) }
func BenchmarkCheck_R100A100Cold(b *testing.B) { runScale(b, 100, 100, true) }

// BenchmarkCheck_R1000A10Hit — 1000 resources × 10 actions = 10000 grants.
func BenchmarkCheck_R1000A10Hit(b *testing.B)  { runScale(b, 1000, 10, false) }
func BenchmarkCheck_R1000A10Cold(b *testing.B) { runScale(b, 1000, 10, true) }

// BenchmarkCheck_R1000A100Hit — 1000 resources × 100 actions = 100000 grants.
func BenchmarkCheck_R1000A100Hit(b *testing.B)  { runScale(b, 1000, 100, false) }
func BenchmarkCheck_R1000A100Cold(b *testing.B) { runScale(b, 1000, 100, true) }
