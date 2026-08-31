package jwt

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Benchmarks cover the hot paths the library is used for: issuing and
// verifying tokens, both for symmetric (HS256) and asymmetric (EdDSA)
// deployments. The numbers reported in README come from these on a
// Ryzen 7 3700X, Go 1.24, Linux/amd64.

var benchClaims = Claims{
	Subject:   "user-1234",
	Issuer:    "bench-issuer",
	Audience:  Audience{"api", "web"},
	ID:        "jti-bench",
	IssuedAt:  time.Unix(1_700_000_000, 0),
	ExpiresAt: time.Unix(1_700_000_900, 0),
}

// benchHS256 builds a Signer / Verifier pair over the package's
// testSecret, primed for -bench.
func benchHS256() (*Signer, *Verifier) {
	s, _ := NewSignerHS256([]byte(testSecret), WithNow(fixedClock(1_700_000_000)))
	v, _ := NewVerifierHS256([]byte(testSecret), WithNow(fixedClock(1_700_000_000)))
	return s, v
}

// benchEdDSA builds an EdDSA pair over a freshly generated key.
func benchEdDSA() (*Signer, *Verifier) {
	pub, priv, _ := ed25519.GenerateKey(cryptorand.Reader)
	s, _ := NewSignerEdDSA(priv, WithNow(fixedClock(1_700_000_000)))
	v, _ := NewVerifierEdDSA(pub, WithNow(fixedClock(1_700_000_000)))
	return s, v
}

func BenchmarkSignHS256(b *testing.B) {
	s, _ := benchHS256()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Sign(benchClaims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyHS256(b *testing.B) {
	s, v := benchHS256()
	token, err := s.Sign(benchClaims)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignEdDSA(b *testing.B) {
	s, _ := benchEdDSA()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Sign(benchClaims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEdDSA(b *testing.B) {
	s, v := benchEdDSA()
	token, err := s.Sign(benchClaims)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLargePayloadHS256 isolates HMAC cost from JSON cost by issuing
// a token whose claims.Extra carries ~1 KiB of payload data.
func BenchmarkLargePayloadHS256(b *testing.B) {
	s, v := benchHS256()
	extra := make(map[string]any, 256)
	filler := strings.Repeat("x", 1024)
	for i := 0; i < 256; i++ {
		extra["k"+strconv.Itoa(i)] = filler
	}
	claims := benchClaims
	claims.Extra = extra
	token, err := s.Sign(claims)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Verify(token); err != nil {
			b.Fatal(err)
		}
	}
}