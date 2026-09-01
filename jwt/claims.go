package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Audience is the "aud" claim. A single audience marshals to a JSON string,
// several to an array; both spellings unmarshal back into an Audience.
type Audience []string

func (a Audience) Contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

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

// reservedClaims are the RFC 7519 §4.1 claim names — typed fields on
// Claims that Extra may not shadow.
var reservedClaims = map[string]struct{}{
	"sub": {},
	"iss": {},
	"aud": {},
	"jti": {},
	"iat": {},
	"exp": {},
	"nbf": {},
}

// Claims is the payload of a libauth identity token. Registered claims
// (RFC 7519 §4.1) are typed fields; anything else round-trips through
// Extra with numbers preserved as json.Number.
type Claims struct {
	Subject   string    // "sub"
	Issuer    string    // "iss"
	Audience  Audience  // "aud"
	ID        string    // "jti"
	IssuedAt  time.Time // "iat" — Sign fills with current time when zero.
	ExpiresAt time.Time // "exp" — Sign requires it, either set or via WithTTL.
	NotBefore time.Time // "nbf"

	// Extra carries non-registered claims. Names in reservedClaims are
	// rejected on encode and never populated on decode.
	Extra map[string]any
}

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

func jsonUnmarshalString(data []byte, out *string) error {
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("must be a string: %w", err)
	}
	return nil
}

// jsonUnmarshalDate decodes a NumericDate (UNIX seconds). A quoted string
// is not a NumericDate per RFC 7519 and is rejected — json.Number would
// otherwise happily accept one.
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

func jsonUnmarshalAny(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

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