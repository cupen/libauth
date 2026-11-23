// Package jwt encodes and decodes compact JWTs (RFC 7519) for libauth
// identities: HS256 with a shared secret, or EdDSA with an Ed25519 key.
//
// The algorithm is pinned at construction, so "none" and cross-algorithm
// confusion are impossible; Decode verifies the signature before parsing
// claims; Encode refuses claims without a subject or expiration.
package jwt

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Supported JOSE algorithm identifiers.
const (
	AlgHS256 = "HS256" // HMAC-SHA-256, shared secret (RFC 7518 §3.2)
	AlgEdDSA = "EdDSA" // Ed25519 (RFC 8037)
)

// Clock returns the current time; inject one via WithNow in tests.
type Clock func() time.Time

// Option customises encoding or decoding. Options are ignored on the side
// they do not apply to: WithTTL / WithIssuer / WithAudience affect Encode,
// WithExpectedIssuer / WithExpectedAudience / WithLeeway affect Decode, and
// WithNow affects both.
type Option func(*settings)

type settings struct {
	ttl            time.Duration
	issuer         string
	audience       Audience
	leeway         time.Duration
	expectIssuer   string
	expectAudience string
	now            Clock
}

func newSettings(opts []Option) *settings {
	s := &settings{now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// WithTTL sets the default validity period Encode applies when claims carry
// no ExpiresAt.
func WithTTL(d time.Duration) Option { return func(s *settings) { s.ttl = d } }

// WithIssuer sets the default Issuer claim applied by Encode.
func WithIssuer(iss string) Option { return func(s *settings) { s.issuer = iss } }

// WithAudience sets the default Audience claim applied by Encode.
func WithAudience(aud ...string) Option { return func(s *settings) { s.audience = aud } }

// WithLeeway sets the tolerated clock skew for the exp, nbf and iat checks.
func WithLeeway(d time.Duration) Option { return func(s *settings) { s.leeway = d } }

// WithExpectedIssuer pins decoding to tokens issued by iss.
func WithExpectedIssuer(iss string) Option { return func(s *settings) { s.expectIssuer = iss } }

// WithExpectedAudience pins decoding to tokens whose aud contains aud.
func WithExpectedAudience(aud string) Option {
	return func(s *settings) { s.expectAudience = aud }
}

// WithNow overrides the clock; nil restores time.Now.
func WithNow(now Clock) Option {
	return func(s *settings) {
		if now == nil {
			now = time.Now
		}
		s.now = now
	}
}

// JWT encodes and decodes tokens for one pinned algorithm. It is safe for
// concurrent use.
type JWT struct {
	alg algorithm
	set *settings
}

// New returns an HS256 JWT keyed with a shared secret of at least 32 bytes
// (RFC 7518 §3.2).
func New(key []byte, opts ...Option) (*JWT, error) {
	alg, err := newHMACAlg(AlgHS256, key)
	if err != nil {
		return nil, err
	}
	return &JWT{alg: alg, set: newSettings(opts)}, nil
}

// NewEdDSA returns an EdDSA JWT that signs with priv.
func NewEdDSA(priv ed25519.PrivateKey, opts ...Option) (*JWT, error) {
	alg, err := newEdDSASignAlg(priv)
	if err != nil {
		return nil, err
	}
	return &JWT{alg: alg, set: newSettings(opts)}, nil
}

// NewVerifierEdDSA returns a verify-only EdDSA JWT; Encode fails with
// ErrInvalidKey.
func NewVerifierEdDSA(pub ed25519.PublicKey, opts ...Option) (*JWT, error) {
	alg, err := newEdDSAVerifyAlg(pub)
	if err != nil {
		return nil, err
	}
	return &JWT{alg: alg, set: newSettings(opts)}, nil
}

func (j *JWT) Algorithm() string { return j.alg.name() }

// Encode issues a compact-serialization token. It fills IssuedAt, ExpiresAt
// (from the TTL when unset), Issuer and Audience from the configured
// defaults, and fails with ErrMissingExpiration when no expiration is
// available.
func (j *JWT) Encode(claims Claims) (string, error) {
	if claims.Subject == "" {
		return "", ErrMissingSubject
	}
	now := j.set.now()
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = now
	}
	if claims.ExpiresAt.IsZero() {
		if j.set.ttl <= 0 {
			return "", ErrMissingExpiration
		}
		claims.ExpiresAt = claims.IssuedAt.Add(j.set.ttl)
	}
	if claims.Issuer == "" {
		claims.Issuer = j.set.issuer
	}
	if len(claims.Audience) == 0 {
		claims.Audience = j.set.audience
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("libauth: encode claims: %w", err)
	}

	input := b64encode(j.alg.header()) + "." + b64encode(payload)
	signature, err := j.alg.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64encode(signature), nil
}

// Decode verifies the signature before parsing claims, then validates exp,
// nbf, iat and the pinned issuer/audience.
func (j *JWT) Decode(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, ErrTokenMalformed
	}

	header, err := b64decode(parts[0])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var jose struct {
		Alg  string   `json:"alg"`
		Typ  string   `json:"typ"`
		Crit []string `json:"crit"`
	}
	if err := json.Unmarshal(header, &jose); err != nil {
		return nil, ErrTokenMalformed
	}
	if jose.Alg != j.alg.name() {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrAlgMismatch, jose.Alg, j.alg.name())
	}
	if jose.Typ != "" && !typIsJWT(jose.Typ) {
		return nil, fmt.Errorf("%w: %q", ErrUnexpectedTyp, jose.Typ)
	}
	if len(jose.Crit) > 0 {
		return nil, ErrUnsupportedCrit
	}

	signature, err := b64decode(parts[2])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	if err := j.alg.verify([]byte(parts[0]+"."+parts[1]), signature); err != nil {
		return nil, err
	}

	payload, err := b64decode(parts[1])
	if err != nil {
		return nil, ErrTokenMalformed
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenMalformed, err)
	}
	if err := j.validate(&claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func (j *JWT) validate(c *Claims) error {
	now := j.set.now()
	if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt.Add(j.set.leeway)) {
		return fmt.Errorf("%w: expired at %s", ErrTokenExpired, c.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore.Add(-j.set.leeway)) {
		return fmt.Errorf("%w: not before %s", ErrTokenNotYetValid, c.NotBefore.UTC().Format(time.RFC3339))
	}
	if !c.IssuedAt.IsZero() && now.Before(c.IssuedAt.Add(-j.set.leeway)) {
		return fmt.Errorf("%w: issued at %s", ErrTokenIssuedInFuture, c.IssuedAt.UTC().Format(time.RFC3339))
	}
	if j.set.expectIssuer != "" && c.Issuer != j.set.expectIssuer {
		return fmt.Errorf("%w: got %q, want %q", ErrIssuerMismatch, c.Issuer, j.set.expectIssuer)
	}
	if j.set.expectAudience != "" && !c.Audience.Contains(j.set.expectAudience) {
		return fmt.Errorf("%w: token carries %v, want %q", ErrAudienceMismatch, []string(c.Audience), j.set.expectAudience)
	}
	return nil
}

func typIsJWT(typ string) bool {
	t := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(typ)), "application/")
	return t == "jwt"
}
