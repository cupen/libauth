// Package model defines the RBAC data types. Persistence and HTTP live
// elsewhere so these types can be serialized, cached or transported as-is.
package model

import (
	"errors"
	"fmt"
	"strings"
)

// Permission is a {Resource, Action} pair. Either field may be "*" as a
// wildcard; {Resource: "*"} alone grants everything.
type Permission struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// ParsePermission parses "resource:action" — "*" parses as {Resource: "*"}.
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

func (p Permission) String() string { return p.Resource + ":" + p.Action }

// Matches reports whether p (a granted pattern) covers required.
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
	return p.Action == "*" || p.Action == required.Action
}

func (p Permission) MatchesAny(required ...Permission) bool {
	for _, r := range required {
		if p.Matches(r) {
			return true
		}
	}
	return false
}

// Valid reports whether the permission is well-formed. {Resource: "*"} is
// valid even with empty Action; everything else needs both fields.
func (p Permission) Valid() bool {
	if p.Resource == "" {
		return false
	}
	return p.Resource == "*" || p.Action != ""
}

func (p Permission) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

func (p *Permission) UnmarshalText(text []byte) error {
	parsed, err := ParsePermission(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}