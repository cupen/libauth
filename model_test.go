package libauth

import "testing"

func TestPermissionValid(t *testing.T) {
	cases := map[Permission]bool{
		"article:create": true,
		"single":         true,  // a segment without colon is fine
		"a:b:c":          true,  // arbitrary depth allowed
		"":               false, // empty
		"a:":             false, // trailing empty segment
		":a":             false, // leading empty segment
		"a::b":           false, // middle empty segment
	}
	for p, want := range cases {
		if got := p.Valid(); got != want {
			t.Errorf("Permission(%q).Valid() = %v, want %v", p, got, want)
		}
	}
}

func TestPermissionMatchesAny(t *testing.T) {
	if !Permission("article:*").MatchesAny("user:read", "article:delete") {
		t.Error("article:* should match article:delete")
	}
	if Permission("user:read").MatchesAny("article:read", "article:write") {
		t.Error("user:read should not match any article permission")
	}
	if !Permission("user:read").MatchesAny("user:read") {
		t.Error("exact match should win")
	}
	if Permission("*").MatchesAny() {
		t.Error("no requirements means nothing can match")
	}
}

func TestRoleHelpers(t *testing.T) {
	r := &Role{
		Name:        "editor",
		Permissions: []Permission{"article:create", "article:edit"},
		Parents:     []RoleName{"viewer", "contributor"},
	}

	if !r.HasParent("viewer") || r.HasParent("admin") {
		t.Error("HasParent lookup failed")
	}
	if !r.HasPermission("article:create") {
		t.Error("role should grant its own permission")
	}
	if r.HasPermission("article:delete") {
		t.Error("role should not grant an unlisted permission")
	}
	if r.HasPermission("article:*") {
		// Semantics: HasPermission treats its argument as the required
		// permission. A wildcard requirement ("grant me everything under
		// article") is only satisfied by a literal granted "*", not by
		// specific grants.
		t.Error("wildcard requirement must not be satisfied by specific grants")
	}
}
