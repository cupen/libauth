package model

import "testing"

func TestParsePermission(t *testing.T) {
	cases := map[string]Permission{
		"article:create": {Resource: "article", Action: "create"},
		"a:b:c":          {Resource: "a", Action: "b:c"},
	}
	for s, want := range cases {
		got, err := ParsePermission(s)
		if err != nil {
			t.Errorf("ParsePermission(%q) error: %v", s, err)
			continue
		}
		if got != want {
			t.Errorf("ParsePermission(%q) = %+v, want %+v", s, got, want)
		}
	}

	for _, bad := range []string{"", "single", ":x", "x:", "::"} {
		if _, err := ParsePermission(bad); err == nil {
			t.Errorf("ParsePermission(%q) should error", bad)
		}
	}
}

func TestPermissionValid(t *testing.T) {
	cases := map[Permission]bool{
		{Resource: "article", Action: "create"}: true,
		{Resource: "*", Action: "x"}:            true,
		{Resource: "*"}:                         true, // global wildcard
		{Resource: "article", Action: "*"}:      true, // per-action wildcard
		{}:                                      false,
		{Resource: "", Action: "x"}:             false,
		{Resource: "x", Action: ""}:             false,
	}
	for p, want := range cases {
		if got := p.Valid(); got != want {
			t.Errorf("%+v.Valid() = %v, want %v", p, got, want)
		}
	}
}

func TestPermissionString(t *testing.T) {
	if s := (Permission{Resource: "article", Action: "create"}).String(); s != "article:create" {
		t.Errorf("String() = %q, want article:create", s)
	}
}

func TestPermissionMatches(t *testing.T) {
	cases := []struct {
		granted, required Permission
		want              bool
	}{
		// exact match
		{Permission{Resource: "article", Action: "create"}, Permission{Resource: "article", Action: "create"}, true},
		// global wildcard grants everything
		{Permission{Resource: "*"}, Permission{Resource: "article", Action: "create"}, true},
		{Permission{Resource: "*"}, Permission{Resource: "user", Action: "delete"}, true},
		// per-action wildcard
		{Permission{Resource: "article", Action: "*"}, Permission{Resource: "article", Action: "delete"}, true},
		{Permission{Resource: "article", Action: "*"}, Permission{Resource: "article", Action: "create"}, true},
		{Permission{Resource: "article", Action: "*"}, Permission{Resource: "user", Action: "delete"}, false},
		// different resource
		{Permission{Resource: "article", Action: "create"}, Permission{Resource: "user", Action: "create"}, false},
		// specific grants do not satisfy a wildcard requirement
		{Permission{Resource: "article", Action: "create"}, Permission{Resource: "article", Action: "*"}, false},
	}
	for _, c := range cases {
		if got := c.granted.Matches(c.required); got != c.want {
			t.Errorf("%+v.Matches(%+v) = %v, want %v", c.granted, c.required, got, c.want)
		}
	}
}

func TestPermissionMatchesAny(t *testing.T) {
	granted := Permission{Resource: "article", Action: "*"}
	userRead := Permission{Resource: "user", Action: "read"}

	if !granted.MatchesAny(
		Permission{Resource: "user", Action: "read"},
		Permission{Resource: "article", Action: "delete"},
	) {
		t.Error("article:* should match article:delete")
	}
	if !granted.MatchesAny(
		Permission{Resource: "article", Action: "read"},
	) {
		t.Error("article:* must match article:read")
	}
	if userRead.MatchesAny(
		Permission{Resource: "article", Action: "read"},
		Permission{Resource: "article", Action: "write"},
	) {
		t.Error("user:read should not match any article permission")
	}
	if !userRead.MatchesAny(
		Permission{Resource: "user", Action: "read"},
	) {
		t.Error("exact match should win")
	}
	global := Permission{Resource: "*"}
	if global.MatchesAny() {
		t.Error("no requirements means nothing can match")
	}
}

func TestPermissionTextRoundTrip(t *testing.T) {
	in := Permission{Resource: "article", Action: "create"}
	b, err := in.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var out Permission
	if err := out.UnmarshalText(b); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Errorf("round-trip = %+v, want %+v", out, in)
	}
}

func TestRoleHelpers(t *testing.T) {
	r := &Role{
		Name: "editor",
		Permissions: []Permission{
			{Resource: "article", Action: "create"},
			{Resource: "article", Action: "edit"},
		},
		Parents: []RoleName{"viewer", "contributor"},
	}

	if !r.HasParent("viewer") || r.HasParent("admin") {
		t.Error("HasParent lookup failed")
	}
	if !r.HasPermission(Permission{Resource: "article", Action: "create"}) {
		t.Error("role should grant its own permission")
	}
	if r.HasPermission(Permission{Resource: "article", Action: "delete"}) {
		t.Error("role should not grant an unlisted permission")
	}
	if r.HasPermission(Permission{Resource: "article", Action: "*"}) {
		t.Error("specific grants must not satisfy a wildcard requirement")
	}
}
