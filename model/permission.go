// Package model defines the core RBAC data types: users, roles and
// permissions. The types are free of persistence and HTTP concerns so they
// can be serialized, cached or transported as-is.
package model

import (
	"errors"
	"fmt"
	"strings"
)

// Permission is a {Resource, Action} pair, e.g. {Resource: "article", Action:
// "create"}.
//
// Wildcards: Resource=="*" alone grants every permission; either field may
// be "*" to match anything in that position (e.g. {Resource: "article",
// Action: "*"} matches every "article:*" permission).
type Permission struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// ParsePermission parses a "resource:action" string. The special case "*"
// parses as {Resource: "*"} (the global wildcard); otherwise both segments
// must be non-empty.
func ParsePermission(s string) (Permission, error) {
	if s == "" {
		return Permission{}, errors.New("empty permission")
	}
	if s == "*" {
		return Permission{Resource: "*"}, nil
	}
	i := strings.IndexByte(s, ':')
	switch {
	case i < 0:
		return Permission{}, fmt.Errorf("permission %q: missing action", s)
	case i == 0:
		return Permission{}, fmt.Errorf("permission %q: empty resource", s)
	case i == len(s)-1:
		return Permission{}, fmt.Errorf("permission %q: empty action", s)
	default:
		return Permission{Resource: s[:i], Action: s[i+1:]}, nil
	}
}

// String renders the permission in canonical "resource:action" form.
func (p Permission) String() string {
	return p.Resource + ":" + p.Action
}

// Matches reports whether p (a granted pattern) covers required (a concrete
// permission being checked).
func (p Permission) Matches(required Permission) bool {
	if p == required {
		return true
	}
	if p.Resource == "*" {
		return true
	}
	if p.Resource != required.Resource {
		return false
	}
	if p.Action == "*" || p.Action == required.Action {
		return true
	}
	return false
}

// MatchesAny reports whether p grants any of the required permissions.
func (p Permission) MatchesAny(required ...Permission) bool {
	for _, r := range required {
		if p.Matches(r) {
			return true
		}
	}
	return false
}

// Valid reports whether the permission is well-formed (resource non-empty,
// action non-empty, or both fields "*").
func (p Permission) Valid() bool {
	if p.Resource == "" {
		return false
	}
	if p.Resource != "*" && p.Action == "" {
		return false
	}
	return true
}

// MarshalText renders the permission as a "resource:action" string.
func (p Permission) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

// UnmarshalText parses a "resource:action" string.
func (p *Permission) UnmarshalText(text []byte) error {
	parsed, err := ParsePermission(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}
