package branca

import (
	"encoding/json"
	"strings"
	"testing"
)

// Benchmarks cover the hot paths the library is used for: issuing and
// verifying encrypted tokens, both as raw bytes and as typed payloads.
// Numbers come from these on a Ryzen 7 3700X, Go 1.24, Linux/amd64.

var benchPayload = []byte(`{"sub":"user-1234","scope":"read write","org":"acme"}`)

type benchSession struct {
	Sub   string `json:"sub,omitempty"`
	Scope string `json:"scope,omitempty"`
}

func (s benchSession) MarshalBinary() ([]byte, error)   { return json.Marshal(s) }
func (s *benchSession) UnmarshalBinary(b []byte) error { return json.Unmarshal(b, s) }

func newBenchBranca() *Branca {
	b, _ := New([]byte(testKey), WithNow(fixedClock(1_700_000_000)))
	return b
}

func BenchmarkEncodeBytes(b *testing.B) {
	bc := newBenchBranca()
	payload := Bytes(append([]byte(nil), benchPayload...))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bc.Encode(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeBytes(b *testing.B) {
	bc := newBenchBranca()
	token, err := bc.Encode(Bytes(benchPayload))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var got Bytes
		if _, err := bc.Decode(token, 0, &got); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeTyped(b *testing.B) {
	bc := newBenchBranca()
	payload := benchSession{Sub: "user-1234", Scope: "read write"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bc.Encode(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeTyped(b *testing.B) {
	bc := newBenchBranca()
	token, err := bc.Encode(benchSession{Sub: "user-1234", Scope: "read write"})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var got benchSession
		if _, err := bc.Decode(token, 0, &got); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLargePayload isolates AEAD cost from JSON cost by sealing a
// ~1 KiB payload.
func BenchmarkLargePayload(b *testing.B) {
	bc := newBenchBranca()
	payload := Bytes(`{"blob":"` + strings.Repeat("x", 1024) + `"}`)
	token, err := bc.Encode(payload)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var got Bytes
		if _, err := bc.Decode(token, 0, &got); err != nil {
			b.Fatal(err)
		}
	}
}