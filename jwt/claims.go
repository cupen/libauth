package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Audience is the "aud" claim: the audiences the token is intended for.
// A single audience marshals to a JSON string, several to an array; both
// spellings unmarshal back into an Audience.
type Audience []string

// Contains reports whether s is listed.
func (a Audience) Contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

// MarshalJSON emits one audience as a string and several as an array.
func (a Audience) MarshalJSON() ([]byte, error) {
	switch len(a) {
	case 0:
		return []byte("null"), nil
	case 1:
		return json.Marshal(a[0])
	default:
		return json.Marshal([]string(a))
	}
}

// UnmarshalJSON accepts a string, an array of strings, or null.
func (a *Audience) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		*a = nil
		return nil
	}
	var one string
	if err := json.Unmarshal(trimmed, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(trimmed, &many); err == nil {
		*a = many
		return nil
	}
	return fmt.Errorf("libauth: aud claim must be a string or an array of strings")
}

// reservedClaims are the registered claim names (RFC 7519 §4.1). They are
// typed fields on Claims and may not be shadowed through Extra.
var reservedClaims = map[string]struct{}{
	"sub": {},
	"iss": {},
	"aud": {},
	"jti": {},
	"iat": {},
	"exp": {},
	"nbf": {},
}

// Claims is the payload of a libauth identity token. The registered claims
// (RFC 7519 §4.1) are typed fields; anything else an issuer puts in the
// payload round-trips through Extra with numbers preserved as json.Number.
type Claims struct {
	// Subject ("sub") — the user ID the token stands for.
	Subject string

	// Issuer ("iss") — who created the token.
	Issuer string

	// Audience ("aud") — who the token is for.
	Audience Audience

	// ID ("jti") — unique token ID, usable for denylists.
	ID string

	// IssuedAt ("iat") — creation time. Sign fills it with the current
	// time when left zero.
	IssuedAt time.Time

	// ExpiresAt ("exp") — hard validity limit. Sign requires it, either
	// set directly or via the signer's WithTTL default.
	ExpiresAt time.Time

	// NotBefore ("nbf") — earliest acceptance time, if any.
	NotBefore time.Time

	// Extra carries non-registered claims. Names in reservedClaims are
	// rejected on encode and never populated on decode.
	Extra map[string]any
}

// MarshalJSON encodes the registered claims in a stable field order and
// merges Extra into the same object. Zero time fields are omitted; times
// are emitted as NumericDate (UNIX seconds).
func (c Claims) MarshalJSON() ([]byte, error) {
	for name := range c.Extra {
		if _, reserved := reservedClaims[name]; reserved {
			return nil, fmt.Errorf("%w: %q", ErrReservedClaim, name)
		}
	}

	type registered struct {
		Subject   string   `json:"sub,omitempty"`
		Issuer    string   `json:"iss,omitempty"`
		Audience  Audience `json:"aud,omitempty"`
		ID        string   `json:"jti,omitempty"`
		IssuedAt  int64    `json:"iat,omitempty"`
		ExpiresAt int64    `json:"exp,omitempty"`
		NotBefore int64    `json:"nbf,omitempty"`
	}
	reg := registered{
		Subject:  c.Subject,
		Issuer:   c.Issuer,
		Audience: c.Audience,
		ID:       c.ID,
	}
	if !c.IssuedAt.IsZero() {
		reg.IssuedAt = c.IssuedAt.Unix()
	}
	if !c.ExpiresAt.IsZero() {
		reg.ExpiresAt = c.ExpiresAt.Unix()
	}
	if !c.NotBefore.IsZero() {
		reg.NotBefore = c.NotBefore.Unix()
	}

	payload, err := json.Marshal(reg)
	if err != nil {
		return nil, err
	}
	if len(c.Extra) == 0 {
		return payload, nil
	}

	merged := make(map[string]json.RawMessage, len(c.Extra)+len(reservedClaims))
	if err := json.Unmarshal(payload, &merged); err != nil {
		return nil, err
	}
	for name, value := range c.Extra {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("libauth: encode claim %q: %w", name, err)
		}
		merged[name] = raw
	}
	return json.Marshal(merged)
}

// UnmarshalJSON parses registered claims into their typed fields and puts
// every other member into Extra (numbers as json.Number). Registered claims
// must have the types RFC 7519 prescribes: strings for sub/iss/jti, a
// string-or-array for aud and numeric dates for iat/exp/nbf.
func (c *Claims) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := jsonUnmarshalStrict(data, &raw); err != nil {
		return err
	}

	parsed := Claims{}
	for name, member := range raw {
		switch name {
		case "sub":
			if err := jsonUnmarshalString(member, &parsed.Subject); err != nil {
				return claimError(name, err)
			}
		case "iss":
			if err := jsonUnmarshalString(member, &parsed.Issuer); err != nil {
				return claimError(name, err)
			}
		case "jti":
			if err := jsonUnmarshalString(member, &parsed.ID); err != nil {
				return claimError(name, err)
			}
		case "aud":
			if err := json.Unmarshal(member, &parsed.Audience); err != nil {
				return claimError(name, err)
			}
		case "iat":
			t, err := jsonUnmarshalDate(member)
			if err != nil {
				return claimError(name, err)
			}
			parsed.IssuedAt = t
		case "exp":
			t, err := jsonUnmarshalDate(member)
			if err != nil {
				return claimError(name, err)
			}
			parsed.ExpiresAt = t
		case "nbf":
			t, err := jsonUnmarshalDate(member)
			if err != nil {
				return claimError(name, err)
			}
			parsed.NotBefore = t
		default:
			value, err := jsonUnmarshalAny(member)
			if err != nil {
				return claimError(name, err)
			}
			if parsed.Extra == nil {
				parsed.Extra = map[string]any{}
			}
			parsed.Extra[name] = value
		}
	}

	if len(parsed.Extra) == 0 {
		parsed.Extra = nil
	}
	*c = parsed
	return nil
}

func claimError(name string, err error) error {
	return fmt.Errorf("libauth: claim %q: %w", name, err)
}

// jsonUnmarshalString decodes a JSON string, rejecting other types.
func jsonUnmarshalString(data []byte, out *string) error {
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("must be a string: %w", err)
	}
	return nil
}

// jsonUnmarshalDate decodes a NumericDate (UNIX seconds) into time.Time.
// A quoted string is not a NumericDate per RFC 7519 and is rejected —
// notably, json.Number would otherwise happily accept one.
func jsonUnmarshalDate(data []byte) (time.Time, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || (trimmed[0] != '-' && (trimmed[0] < '0' || trimmed[0] > '9')) {
		return time.Time{}, fmt.Errorf("must be a numeric date (UNIX seconds)")
	}
	var number json.Number
	if err := json.Unmarshal(trimmed, &number); err != nil {
		return time.Time{}, fmt.Errorf("must be a numeric date (UNIX seconds): %w", err)
	}
	seconds, err := number.Int64()
	if err != nil {
		return time.Time{}, fmt.Errorf("must be a whole-number UNIX timestamp: %w", err)
	}
	return time.Unix(seconds, 0).UTC(), nil
}

// jsonUnmarshalAny decodes any JSON value, preserving numbers as
// json.Number instead of lossy float64.
func jsonUnmarshalAny(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// jsonUnmarshalStrict decodes data into out, rejecting trailing garbage.
func jsonUnmarshalStrict(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("libauth: trailing data after JSON object")
	}
	return nil
}
