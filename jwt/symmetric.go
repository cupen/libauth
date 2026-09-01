package jwt

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// JWT is the high-level, symmetric view of the package: one object that
// both encodes and decodes tokens for a single pinned algorithm. It mirrors
// the branca package's shape (one type, New / Encode / Decode) so a caller
// who learned one can read the other.
//
// JWT wraps a Signer and a Verifier bound to the same algorithm. Options
// like WithTTL / WithIssuer flow to the signer; WithExpectedIssuer /
// WithExpectedAudience / WithLeeway to the verifier.
//
//	auth, err := jwt.New(secret,
//	    jwt.WithTTL(15*time.Minute),
//	    jwt.WithIssuer("login"),
//	    jwt.WithExpectedIssuer("login"),
//	)
//	token, err := auth.Encode(jwt.Claims{Subject: "bob"})
//	claims, err := auth.Decode(token)
type JWT struct {
	sign   *Signer
	verify *Verifier
}

// New returns a JWT that signs and verifies HS256 tokens with a shared
// secret. The secret must be at least 32 bytes (RFC 7518 §3.2).
func New(key []byte, opts ...Option) (*JWT, error) {
	s, err := NewSignerHS256(key, opts...)
	if err != nil {
		return nil, err
	}
	v, err := NewVerifierHS256(key, opts...)
	if err != nil {
		return nil, err
	}
	return &JWT{sign: s, verify: v}, nil
}

// NewEdDSA returns a JWT that signs with priv and verifies with pub. priv
// is required — verify-only flows use NewVerifierEdDSA directly.
func NewEdDSA(priv ed25519.PrivateKey, pub ed25519.PublicKey, opts ...Option) (*JWT, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: EdDSA private key is required for signing", ErrInvalidKey)
	}
	s, err := NewSignerEdDSA(priv, opts...)
	if err != nil {
		return nil, err
	}
	v, err := NewVerifierEdDSA(pub, opts...)
	if err != nil {
		return nil, err
	}
	return &JWT{sign: s, verify: v}, nil
}

func (j *JWT) Algorithm() string { return j.sign.Algorithm() }

// Encode issues a compact-serialization token for the supplied claims.
func (j *JWT) Encode(claims Claims) (string, error) { return j.sign.Sign(claims) }

// Decode verifies the token's structure and signature, then validates the
// registered time claims and pinned issuer/audience.
func (j *JWT) Decode(token string) (*Claims, error) { return j.verify.Verify(token) }

// ExampleJWT demonstrates the symmetric high-level type: one constructor
// binds signing and verification, options flow to the side they apply to,
// and the resulting object round-trips a Claims through Encode / Decode.
func ExampleJWT() {
	auth, _ := New([]byte("0123456789abcdef0123456789abcdef"),
		WithTTL(15*time.Minute),
		WithIssuer("login"),
		WithExpectedIssuer("login"),
	)
	tok, _ := auth.Encode(Claims{Subject: "bob"})
	out, _ := auth.Decode(tok)
	fmt.Println(out.Subject, out.Issuer)

	// Output:
	// bob login
}