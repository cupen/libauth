// Package jwt implements a minimal, dependency-free JWT signer and verifier
// (RFC 7519) for carrying libauth identities.
//
// Security posture:
//
//   - The algorithm is pinned by construction: a Verifier only accepts
//     tokens signed with the exact algorithm it was built for, so the
//     "none" algorithm and cross-algorithm confusion attacks are
//     structurally impossible.
//   - Only HS256 (HMAC-SHA-256, shared secret) and EdDSA (Ed25519) are
//     supported. Both ship with the Go standard library, which keeps
//     libauth free of third-party dependencies.
//   - Signatures are verified before any claim is parsed. exp, nbf and iat
//     are enforced (with optional leeway); iss and aud can be pinned.
//   - Sign refuses claims without an expiration unless a default TTL is
//     configured, so tokens that never expire cannot be created by accident.
//
// Typical use — sign where users log in, verify where requests arrive:
//
//	signer, err := jwt.NewSignerHS256(secret, jwt.WithTTL(15*time.Minute))
//	token, err := signer.Sign(jwt.Claims{Subject: "bob"})
//
//	verifier, err := jwt.NewVerifierHS256(secret, jwt.WithExpectedIssuer("login"))
//	claims, err := verifier.Verify(token)
//
// Use HS256 when the issuer and every verifier live in one trust boundary
// and can share a secret; use EdDSA when several services must verify
// tokens that only the issuer can create (verifiers hold the public key
// only). libauth.BearerIdentity wires a Verifier straight into the HTTP
// middleware as an identity source.
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
	// AlgHS256 is HMAC using SHA-256 with a shared secret (RFC 7518 §3.2).
	AlgHS256 = "HS256"

	// AlgEdDSA is Ed25519 digital signature (RFC 8037).
	AlgEdDSA = "EdDSA"
)

// Clock returns the current time. Inject one via WithNow to make signing
// and verification deterministic (mostly for tests).
type Clock func() time.Time

// Option customises a signer or a verifier. Options that do not apply to
// the constructor they are passed to are ignored.
type Option func(*settings)

type settings struct {
	// signer: default ExpiresAt applied when signed claims carry none.
	ttl time.Duration
	// signer: default Issuer / Audience applied when claims leave them empty.
	issuer   string
	audience Audience
	// verifier: tolerated clock skew around exp/nbf/iat checks.
	leeway time.Duration
	// verifier: pinned iss / aud when non-empty.
	expectIssuer   string
	expectAudience string
	// both: injectable clock.
	now Clock
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

// WithTTL sets the signer's default validity period, used when signed
// claims do not carry an ExpiresAt. Verifiers ignore it.
func WithTTL(d time.Duration) Option { return func(s *settings) { s.ttl = d } }

// WithIssuer sets the signer's default Issuer claim, used when signed
// claims leave it empty. Verifiers ignore it.
func WithIssuer(iss string) Option { return func(s *settings) { s.issuer = iss } }

// WithAudience sets the signer's default Audience claim, used when signed
// claims leave it empty. Verifiers ignore it.
func WithAudience(aud ...string) Option { return func(s *settings) { s.audience = aud } }

// WithLeeway sets the verifier's tolerated clock skew for exp, nbf and iat
// checks. The default is zero: strict comparison against the verifier's
// clock. Signers ignore it.
func WithLeeway(d time.Duration) Option { return func(s *settings) { s.leeway = d } }

// WithExpectedIssuer pins the verifier to tokens issued by iss; tokens
// with a different iss claim are rejected. Empty disables the check.
func WithExpectedIssuer(iss string) Option { return func(s *settings) { s.expectIssuer = iss } }

// WithExpectedAudience pins the verifier to tokens whose aud claim contains
// aud. Empty disables the check.
func WithExpectedAudience(aud string) Option {
	return func(s *settings) { s.expectAudience = aud }
}

// WithNow overrides the clock used for iat/exp arithmetic on both signers
// and verifiers. nil restores time.Now. Mostly useful in tests.
func WithNow(now Clock) Option {
	return func(s *settings) {
		if now == nil {
			now = time.Now
		}
		s.now = now
	}
}

// Signer issues compact-serialization JWTs for one pinned algorithm.
type Signer struct {
	alg algorithm
	set *settings
}

// Verifier validates compact-serialization JWTs for one pinned algorithm.
type Verifier struct {
	alg algorithm
	set *settings
}

// NewSignerHS256 returns an HS256 signer keyed with a shared secret. The
// secret must be at least 32 bytes (the SHA-256 output size, RFC 7518 §3.2).
func NewSignerHS256(key []byte, opts ...Option) (*Signer, error) {
	alg, err := newHMACAlg(AlgHS256, key)
	if err != nil {
		return nil, err
	}
	return &Signer{alg: alg, set: newSettings(opts)}, nil
}

// NewSignerEdDSA returns an EdDSA (Ed25519) signer keyed with a private key;
// generate one with ed25519.GenerateKey. The matching verifier takes the
// public half only.
func NewSignerEdDSA(key ed25519.PrivateKey, opts ...Option) (*Signer, error) {
	alg, err := newEdDSASignAlg(key)
	if err != nil {
		return nil, err
	}
	return &Signer{alg: alg, set: newSettings(opts)}, nil
}

// NewVerifierHS256 returns an HS256 verifier keyed with the shared secret
// the issuer used (at least 32 bytes).
func NewVerifierHS256(key []byte, opts ...Option) (*Verifier, error) {
	alg, err := newHMACAlg(AlgHS256, key)
	if err != nil {
		return nil, err
	}
	return &Verifier{alg: alg, set: newSettings(opts)}, nil
}

// NewVerifierEdDSA returns an EdDSA (Ed25519) verifier keyed with the
// issuer's public key. It cannot sign tokens.
func NewVerifierEdDSA(key ed25519.PublicKey, opts ...Option) (*Verifier, error) {
	alg, err := newEdDSAVerifyAlg(key)
	if err != nil {
		return nil, err
	}
	return &Verifier{alg: alg, set: newSettings(opts)}, nil
}

// Algorithm reports the pinned JOSE alg value.
func (s *Signer) Algorithm() string { return s.alg.name() }

// Algorithm reports the pinned JOSE alg value; Verify rejects every other.
func (v *Verifier) Algorithm() string { return v.alg.name() }

// Sign marshals the claims, signs them and returns the compact JWT
// "header.payload.signature".
//
// Defaults applied to the claims before signing: IssuedAt becomes now when
// zero; ExpiresAt becomes IssuedAt plus the configured TTL when zero (and
// Sign fails with ErrMissingExpiration if no TTL is configured either);
// Issuer and Audience fall back to the configured values when empty.
func (s *Signer) Sign(claims Claims) (string, error) {
	now := s.set.now()
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = now
	}
	if claims.ExpiresAt.IsZero() {
		if s.set.ttl <= 0 {
			return "", ErrMissingExpiration
		}
		claims.ExpiresAt = claims.IssuedAt.Add(s.set.ttl)
	}
	if claims.Issuer == "" {
		claims.Issuer = s.set.issuer
	}
	if len(claims.Audience) == 0 {
		claims.Audience = s.set.audience
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("libauth: encode claims: %w", err)
	}

	input := b64encode(s.alg.header()) + "." + b64encode(payload)
	signature, err := s.alg.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64encode(signature), nil
}

// Verify checks the token's structure and signature, then validates the
// registered time claims (exp, nbf, iat, each with the configured leeway)
// and the pinned iss/aud when configured. It returns the parsed claims,
// with non-registered payload members available through Claims.Extra.
//
// The order matters: the signature is checked before the payload is parsed,
// so untrusted input never reaches claim handling unauthenticated.
func (v *Verifier) Verify(token string) (*Claims, error) {
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
	if jose.Alg != v.alg.name() {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrAlgMismatch, jose.Alg, v.alg.name())
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
	if err := v.alg.verify([]byte(parts[0]+"."+parts[1]), signature); err != nil {
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
	if err := v.validate(&claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// validate enforces the registered time claims and pinned issuer/audience.
func (v *Verifier) validate(c *Claims) error {
	now := v.set.now()
	if !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt.Add(v.set.leeway)) {
		return fmt.Errorf("%w: expired at %s", ErrTokenExpired, c.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore.Add(-v.set.leeway)) {
		return fmt.Errorf("%w: not before %s", ErrTokenNotYetValid, c.NotBefore.UTC().Format(time.RFC3339))
	}
	if !c.IssuedAt.IsZero() && now.Before(c.IssuedAt.Add(-v.set.leeway)) {
		return fmt.Errorf("%w: issued at %s", ErrTokenIssuedInFuture, c.IssuedAt.UTC().Format(time.RFC3339))
	}
	if v.set.expectIssuer != "" && c.Issuer != v.set.expectIssuer {
		return fmt.Errorf("%w: got %q, want %q", ErrIssuerMismatch, c.Issuer, v.set.expectIssuer)
	}
	if v.set.expectAudience != "" && !c.Audience.Contains(v.set.expectAudience) {
		return fmt.Errorf("%w: token carries %v, want %q", ErrAudienceMismatch, []string(c.Audience), v.set.expectAudience)
	}
	return nil
}

// typIsJWT reports whether the optional typ header identifies a JWT. The
// header carries no security weight (the algorithm is pinned separately),
// so conventional spellings are accepted and anything else fails loudly.
func typIsJWT(typ string) bool {
	t := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(typ)), "application/")
	return t == "jwt"
}

// VerifyBearer verifies token and returns the user ID its sub claim names —
// the adapter libauth.BearerIdentity expects. Tokens without a usable sub
// claim fail with ErrTokenWithoutSubject.
func (v *Verifier) VerifyBearer(token string) (string, error) {
	claims, err := v.Verify(token)
	if err != nil {
		return "", err
	}
	if claims.Subject == "" {
		return "", ErrTokenWithoutSubject
	}
	return claims.Subject, nil
}
