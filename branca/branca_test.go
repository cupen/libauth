package branca

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// testKey is the secret shared by the official branca test vectors
// (tuupola/branca-php tests/BrancaTest.php, mandatory for every
// implementation): 32 bytes.
const testKey = "supersecretkeyyoushouldnotcommit"

// session is a JSON-backed payload type exercising the typed Branca API.
type session struct {
	Sub   string `json:"sub,omitempty"`
	Scope string `json:"scope,omitempty"`
}

func (s session) MarshalBinary() ([]byte, error) { return json.Marshal(s) }

func (s *session) UnmarshalBinary(raw []byte) error { return json.Unmarshal(raw, s) }

// noopUnmarshaler discards the payload — useful in tests that only care
// about decoding side-effects (timestamp, errors) and not the bytes.
type noopUnmarshaler struct{}

func (noopUnmarshaler) UnmarshalBinary([]byte) error { return nil }

type failingMarshaler struct{}

func (failingMarshaler) MarshalBinary() ([]byte, error) {
	return nil, errors.New("boom")
}

func newTestBranca(t *testing.T, opts ...Option) *Branca {
	t.Helper()
	c, err := New([]byte(testKey), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func fixedClock(unix int64) Clock {
	return func() time.Time { return time.Unix(unix, 0) }
}

// TestOfficialDecodeVectors runs the mandatory cross-implementation decode
// vectors, including the timestamp extremes and binary payloads.
func TestOfficialDecodeVectors(t *testing.T) {
	eightZeros := "\x00\x00\x00\x00\x00\x00\x00\x00"
	cases := []struct {
		name    string
		token   string
		payload string
		ts      uint32
	}{
		{"hello world, ts 0", "870S4BYxgHw0KnP3W9fgVUHEhT5g86vJ17etaC5Kh5uIraWHCI1psNQGv298ZmjPwoYbjDQ9chy2z", "Hello world!", 0},
		{"hello world, ts max", "89i7YCwu5tWAJNHUDdmIqhzOi5hVHOd4afjZcGMcVmM4enl4yeLiDyYv41eMkNmTX6IwYEFErCSqr", "Hello world!", 4294967295},
		{"hello world, beef nonce", "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT", "Hello world!", 123206400},
		{"zero payload, ts 0", "1jIBheHbDdkCDFQmtgw4RUZeQoOJgGwTFJSpwOAk3XYpJJr52DEpILLmmwYl4tjdSbbNqcF1", eightZeros, 0},
		{"zero payload, ts max", "1jrx6DUu5q06oxykef2e2ZMyTcDRTQot9ZnwgifUtzAphGtjsxfbxXNhQyBEOGtpbkBgvIQx", eightZeros, 4294967295},
		{"zero payload, ts mid", "1jJDJOEjuwVb9Csz1Ypw1KBWSkr0YDpeBeJN6NzJWx1VgPLmcBhu2SbkpQ9JjZ3nfUf7Aytp", eightZeros, 123206400},
		{"empty payload", "4sfD0vPFhIif8cy4nB3BQkHeJqkOkDvinI4zIhMjYX4YXZU5WIq9ycCVjGzB5", "", 0},
		{"single 0x80 payload", "K9u6d0zjXp8RXNUGDyXAsB9AtPo60CD3xxQ2ulL8aQoTzXbvockRff0y1eXoHm", "\x80", 123206400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := newTestBranca(t).Decode(tc.token, 0, noopUnmarshaler{})
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !bytes.Equal(tok.Payload, []byte(tc.payload)) {
				t.Fatalf("payload = %x, want %x", tok.Payload, tc.payload)
			}
			if got := tok.Timestamp.Unix(); got != int64(tc.ts) {
				t.Fatalf("timestamp = %d, want %d", got, tc.ts)
			}
		})
	}
}

// TestOfficialNegativeVectors runs the tokens every implementation must
// reject: wrong version, invalid base62, and every kind of tampering.
func TestOfficialNegativeVectors(t *testing.T) {
	malformed := []struct {
		name  string
		token string
	}{
		{"wrong version", "89mvl3RkwXjpEj5WMxK7GUDEHEeeeZtwjMIOogTthvr44qBfYtQSIZH5MHOTC0GzoutDIeoPVZk3w"},
		{"invalid base62 character", "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT_"},
		{"modified version byte", "89mvl3S0BE0UCMIY94xxIux4eg1w5oXrhvCEXrDAjusSbO0Yk7AU6FjjTnbTWTqogLfNPJLzecHVb"},
	}
	for _, tc := range malformed {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newTestBranca(t).Decode(tc.token, 0, noopUnmarshaler{}); !errors.Is(err, ErrTokenMalformed) {
				t.Fatalf("Decode: err = %v, want ErrTokenMalformed", err)
			}
		})
	}

	invalid := []struct {
		name  string
		token string
	}{
		{"modified nonce", "875GH233SUysT7fQ711EWd9BXpwOjB72ng3ZLnjWFrmOqVy49Bv93b78JU5331LbcY0EEzhLfpmSx"},
		{"modified timestamp", "870g1RCk4lW1YInhaU3TP8u2hGtfol16ettLcTOSoA0JIpjCaQRW7tQeP6dQmTvFIB2s6wL5deMXr"},
		{"modified ciphertext", "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trk0"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newTestBranca(t).Decode(tc.token, 0, noopUnmarshaler{}); !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("Decode: err = %v, want ErrTokenInvalid", err)
			}
		})
	}

	t.Run("wrong key", func(t *testing.T) {
		c, err := New([]byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := c.Decode("875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT", 0, noopUnmarshaler{}); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("Decode: err = %v, want ErrTokenInvalid", err)
		}
	})
}

// TestEncodeMatchesOfficialVector derives the encode direction from the
// documented provenance of decode vector 10: nonce beef repeated 12 times,
// timestamp 0x0757fb00, payload "Hello world!".
func TestEncodeMatchesOfficialVector(t *testing.T) {
	c := newTestBranca(t,
		WithNow(fixedClock(123206400)),
		WithRand(bytes.NewReader(bytes.Repeat([]byte{0xBE, 0xEF}, 12))),
	)
	token, err := c.Encode(Bytes("Hello world!"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	const want = "875GH23U0Dr6nHFA63DhOyd9LkYudBkX8RsCTOMz5xoYAMw9sMd5QwcEqLDRnTDHPenOX7nP2trlT"
	if token != want {
		t.Fatalf("Encode mismatch:\n got %s\nwant %s", token, want)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte("Hello world!"),
		{},
		bytes.Repeat([]byte{0x00}, 16),
		[]byte(`{"sub":"bob","team":"core"}`),
	} {
		token, err := newTestBranca(t, WithNow(fixedClock(1000))).Encode(Bytes(payload))
		if err != nil {
			t.Fatalf("Encode(%x): %v", payload, err)
		}
		tok, err := newTestBranca(t, WithNow(fixedClock(1000))).Decode(token, 0, noopUnmarshaler{})
		if err != nil {
			t.Fatalf("Decode(%x): %v", payload, err)
		}
		if !bytes.Equal(tok.Payload, payload) {
			t.Fatalf("payload = %x, want %x", tok.Payload, payload)
		}
		if !tok.Timestamp.Equal(time.Unix(1000, 0).UTC()) {
			t.Fatalf("timestamp = %v, want unix 1000", tok.Timestamp)
		}
	}
}

func TestDecodeTTL(t *testing.T) {
	token, err := newTestBranca(t, WithNow(fixedClock(1000))).Encode(Bytes("x"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	cases := []struct {
		name   string
		opened int64         // clock of the opening codec
		ttl    time.Duration // ttl passed to Decode
		want   error
	}{
		{"no ttl", 999999, 0, nil},
		{"within ttl", 1000 + 1800, 30 * time.Minute, nil},
		{"ttl boundary", 1000 + 1800 - 1, 30 * time.Minute, nil},
		{"expired", 1000 + 1800 + 1, 30 * time.Minute, ErrTokenExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestBranca(t, WithNow(fixedClock(tc.opened))).Decode(token, tc.ttl, noopUnmarshaler{})
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Decode: unexpected error %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Decode: err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestMalformedTokens(t *testing.T) {
	c := newTestBranca(t)
	for _, token := range []string{"", "abc", strings.Repeat("1", 60), "!!!"} {
		if _, err := c.Decode(token, 0, noopUnmarshaler{}); !errors.Is(err, ErrTokenMalformed) {
			t.Errorf("Decode(%q): err = %v, want ErrTokenMalformed", token, err)
		}
	}

	// A well-formed base62 token whose version byte is not 0xBA.
	bogus := base62Encode(append([]byte{0xBB}, make([]byte, 44)...))
	if _, err := c.Decode(bogus, 0, noopUnmarshaler{}); !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("Decode(0xBB token): err = %v, want ErrTokenMalformed", err)
	}
}

func TestEncodeTimestampRange(t *testing.T) {
	if _, err := newTestBranca(t, WithNow(fixedClock(-1))).Encode(Bytes(nil)); err == nil {
		t.Error("negative timestamp must be rejected")
	}
	if _, err := newTestBranca(t, WithNow(fixedClock(int64(4294967295)+1))).Encode(Bytes(nil)); err == nil {
		t.Error("timestamp beyond 2106 must be rejected")
	}
	if _, err := newTestBranca(t, WithNow(fixedClock(int64(4294967295)))).Encode(Bytes(nil)); err != nil {
		t.Errorf("Encode at max uint32 timestamp: %v", err)
	}
}

func TestInvalidKeys(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := New(key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("New(%d bytes): err = %v, want ErrInvalidKey", len(key), err)
		}
	}
	if _, err := New(make([]byte, 32)); err != nil {
		t.Errorf("New(32 bytes): %v", err)
	}
}

func TestBase62(t *testing.T) {
	// Digit values: digits first, then A-Z (10..35), then a-z (36..61).
	if got := base62Encode([]byte{0xBA}); got != "30" { // 186 = 3*62 + 0
		t.Errorf("encode(0xBA) = %q, want %q", got, "30")
	}
	if got, _ := base62Decode("1A"); !bytes.Equal(got, []byte{0x48}) { // 1*62+10 = 72
		t.Errorf(`decode("1A") = %x, want 48`, got)
	}
	if got, err := base62Decode("1a"); err != nil || !bytes.Equal(got, []byte{0x62}) { // 1*62+36 = 98
		t.Errorf(`decode("1a") = %x, err = %v; want 62`, got, err)
	}
	if _, err := base62Decode("-1"); err == nil {
		t.Error("sign prefix must be rejected")
	}
	if _, err := base62Decode("1_1"); err == nil {
		t.Error("non-alphabet character must be rejected")
	}

	// Property: decode(encode(x)) == x. Branca binaries always start with
	// the non-zero version byte, so leading-zero inputs are out of scope.
	for _, raw := range [][]byte{
		{0xBA}, {0x01, 0x3E}, []byte("Hello world!"), bytes.Repeat([]byte{0xFF}, 45),
	} {
		got, err := base62Decode(base62Encode(raw))
		if err != nil {
			t.Fatalf("round trip %x: %v", raw, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("round trip %x: got %x", raw, got)
		}
	}
}

func TestBrancaEncodeDecode(t *testing.T) {
	b, err := New([]byte(testKey), WithNow(fixedClock(1000)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token, err := b.Encode(session{Sub: "bob", Scope: "read"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got session
	tok, err := b.Decode(token, 0, &got)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != (session{Sub: "bob", Scope: "read"}) {
		t.Fatalf("value = %+v, want bob/read", got)
	}
	if tok.Timestamp.IsZero() {
		t.Error("Token.Timestamp should be populated")
	}

	// A payload the type cannot decode is a malformed token, not a panic.
	raw, err := b.Encode(Bytes("not json"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := b.Decode(raw, 0, &got); !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("Decode(non-JSON): err = %v, want ErrTokenMalformed", err)
	}
}

func TestBrancaEncodeError(t *testing.T) {
	b, err := New([]byte(testKey))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := b.Encode(failingMarshaler{}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Encode: err = %v, want the MarshalBinary failure", err)
	}
}

// TestBearerIdentification exercises the bearer-token round-trip the way a
// real IdentityFunc would: Decode the token, read the sub claim. The
// dedicated VerifyBearer method that used to live on *Branca was removed
// in favour of this caller-side flow.
func TestBearerIdentification(t *testing.T) {
	const ttl = time.Hour
	b, err := New([]byte(testKey), WithNow(fixedClock(4000)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, err := b.Encode(session{Sub: "bob"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	identify := func(tok string) (string, error) {
		var s session
		if _, err := b.Decode(tok, ttl, &s); err != nil {
			return "", err
		}
		if s.Sub == "" {
			return "", errors.New("token has no sub claim")
		}
		return s.Sub, nil
	}

	if subject, err := identify(token); err != nil || subject != "bob" {
		t.Fatalf("identify = %q, %v; want bob, nil", subject, err)
	}

	// An expired token is rejected even though it authenticates fine.
	expiredB, err := New([]byte(testKey), WithNow(fixedClock(0)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	expired, err := expiredB.Encode(session{Sub: "bob"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := identify(expired); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("identify expired: err = %v, want ErrTokenExpired", err)
	}

	// A payload naming no user must not authenticate as the empty user.
	anonymous, err := b.Encode(session{Scope: "read"})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := identify(anonymous); err == nil || !strings.Contains(err.Error(), "sub") {
		t.Fatalf("identify anonymous: err = %v, want sub error", err)
	}

	// Payloads that are not objects that can be decoded into a session.
	for _, payload := range []string{`{"sub":42}`, `"str"`, "", `{"sub":"a"} trailing`} {
		raw, err := b.Encode(Bytes(payload))
		if err != nil {
			t.Fatalf("Encode(%q): %v", payload, err)
		}
		if _, err := identify(raw); !errors.Is(err, ErrTokenMalformed) {
			t.Errorf("identify(%q): err = %v, want ErrTokenMalformed", payload, err)
		}
	}
}

func TestBytesRoundTrip(t *testing.T) {
	b, err := New([]byte(testKey), WithNow(fixedClock(1000)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	want := Bytes("opaque-binary-payload")
	token, err := b.Encode(want)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var got Bytes
	if _, err := b.Decode(token, 0, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload = %x, want %x", got, want)
	}
}