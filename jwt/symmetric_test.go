package jwt

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedClock mirrors the helper used by jwt_test.go.
func fixedClockSym(t int64) Clock {
	return func() time.Time { return time.Unix(t, 0) }
}

// TestJWTSymmetricHS256 covers the happy path of the high-level type: one
// constructor binds sign + verify on the same key, and Encode / Decode
// round-trip a Claims while honouring WithTTL and WithExpectedIssuer.
func TestJWTSymmetricHS256(t *testing.T) {
	auth, err := New([]byte(testSecret),
		WithTTL(30*time.Minute),
		WithIssuer("login"),
		WithExpectedIssuer("login"),
		WithNow(fixedClockSym(1_700_000_000)),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := auth.Algorithm(); got != AlgHS256 {
		t.Errorf("Algorithm = %q, want %q", got, AlgHS256)
	}

	token, err := auth.Encode(Claims{Subject: "bob"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token shape: %q is not 3 segments", token)
	}

	claims, err := auth.Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if claims.Subject != "bob" {
		t.Errorf("Subject = %q, want bob", claims.Subject)
	}
	if claims.Issuer != "login" {
		t.Errorf("Issuer = %q, want login", claims.Issuer)
	}
	if claims.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be filled by WithTTL on the signer")
	}
}

// TestJWTSymmetricHS256MismatchKey covers the case where a token issued by a
// different secret cannot be decoded.
func TestJWTSymmetricHS256MismatchKey(t *testing.T) {
	a, err := New([]byte(testSecret), WithTTL(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([]byte("fedcba9876543210fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.Encode(Claims{Subject: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Decode(token); !errors.Is(err, ErrTokenBadSignature) {
		t.Fatalf("Decode across mismatched secrets: err = %v, want ErrTokenBadSignature", err)
	}
}

// TestJWTSymmetricHS256MissingSubject confirms the high-level type rejects
// empty-Subject encodes, mirroring what the underlying Signer does.
func TestJWTSymmetricHS256MissingSubject(t *testing.T) {
	auth, err := New([]byte(testSecret), WithTTL(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Encode(Claims{}); !errors.Is(err, ErrMissingSubject) {
		t.Fatalf("Encode empty: err = %v, want ErrMissingSubject", err)
	}
}

// TestJWTSymmetricEdDSA confirms the asymmetric variant binds a private
// signer and a public verifier around the same EdDSA algorithm.
func TestJWTSymmetricEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewEdDSA(priv, pub, WithTTL(time.Hour), WithNow(fixedClockSym(100)))
	if err != nil {
		t.Fatalf("NewEdDSA: %v", err)
	}
	if got := auth.Algorithm(); got != AlgEdDSA {
		t.Errorf("Algorithm = %q, want %q", got, AlgEdDSA)
	}
	token, err := auth.Encode(Claims{Subject: "carol"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := auth.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "carol" {
		t.Errorf("Subject = %q, want carol", claims.Subject)
	}
}

// TestJWTSymmetricEdDSANilPrivate ensures we never accept an EdDSA binding
// without a private key — Decode-only flows still need a verifier to be
// constructed through NewVerifierEdDSA directly.
func TestJWTSymmetricEdDSANilPrivate(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEdDSA(nil, pub); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewEdDSA(nil): err = %v, want ErrInvalidKey", err)
	}
}