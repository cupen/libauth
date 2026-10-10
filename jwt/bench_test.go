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

// benchHS256 builds an encode / decode pair over the package's
// testSecret, primed for -bench.
func benchHS256() (*JWT, *JWT) {
	enc, _ := New([]byte(testSecret), WithNow(fixedClock(1_700_000_000)))
	dec, _ := New([]byte(testSecret), WithNow(fixedClock(1_700_000_000)))
	return enc, dec
}

// benchEdDSA builds an EdDSA encoder and a verify-only decoder over a freshly generated key.
func benchEdDSA() (*JWT, *JWT) {
	pub, priv, _ := ed25519.GenerateKey(cryptorand.Reader)
	enc, _ := NewEdDSA(priv, WithNow(fixedClock(1_700_000_000)))
	dec, _ := NewVerifierEdDSA(pub, WithNow(fixedClock(1_700_000_000)))
	return enc, dec
}

func BenchmarkEncodeHS256(b *testing.B) {
	enc, _ := benchHS256()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := enc.Encode(benchClaims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeHS256(b *testing.B) {
	enc, dec := benchHS256()
	token, err := enc.Encode(benchClaims)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dec.Decode(token); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeEdDSA(b *testing.B) {
	enc, _ := benchEdDSA()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := enc.Encode(benchClaims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeEdDSA(b *testing.B) {
	enc, dec := benchEdDSA()
	token, err := enc.Encode(benchClaims)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dec.Decode(token); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLargePayloadHS256 isolates HMAC cost from JSON cost by issuing
// a token whose claims.Extra carries ~1 KiB of payload data.
func BenchmarkLargePayloadHS256(b *testing.B) {
	enc, dec := benchHS256()
	extra := make(map[string]any, 256)
	filler := strings.Repeat("x", 1024)
	for i := 0; i < 256; i++ {
		extra["k"+strconv.Itoa(i)] = filler
	}
	claims := benchClaims
	claims.Extra = extra
	token, err := enc.Encode(claims)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dec.Decode(token); err != nil {
			b.Fatal(err)
		}
	}
}
