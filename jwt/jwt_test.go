package jwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef" // 48 bytes

// goldenHS256 was produced independently with:
//
//	printf '%s.%s' "$H" "$P" \
//	  | openssl dgst -sha256 -hmac "$testSecret" -binary \
//	  | basenc --base64url | tr -d '='
//
// over header {"alg":"HS256","typ":"JWT"} and payload
// {"sub":"alice","iat":1600000000,"exp":1600003600}.
const goldenHS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
	"eyJzdWIiOiJhbGljZSIsImlhdCI6MTYwMDAwMDAwMCwiZXhwIjoxNjAwMDAzNjAwfQ." +
	"GZ7vkr4RpjqUApYh892l-rF20mWhfACODbH3R-MML4c"

const goldenPayload = `{"sub":"alice","iat":1600000000,"exp":1600003600}`

func fixedClock(unix int64) Clock {
	return func() time.Time { return time.Unix(unix, 0) }
}

func mustSigner(t *testing.T, opts ...Option) *Signer {
	t.Helper()
	s, err := NewSignerHS256([]byte(testSecret), opts...)
	if err != nil {
		t.Fatalf("NewSignerHS256: %v", err)
	}
	return s
}

func mustVerifier(t *testing.T, opts ...Option) *Verifier {
	t.Helper()
	v, err := NewVerifierHS256([]byte(testSecret), opts...)
	if err != nil {
		t.Fatalf("NewVerifierHS256: %v", err)
	}
	return v
}

// craftToken builds a properly signed HS256 token with an arbitrary JOSE
// header and payload, for testing paths Sign does not let you configure.
func craftToken(t *testing.T, headerJSON, payloadJSON string) string {
	t.Helper()
	input := b64encode([]byte(headerJSON)) + "." + b64encode([]byte(payloadJSON))
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(input))
	return input + "." + b64encode(mac.Sum(nil))
}

func TestHS256GoldenVector(t *testing.T) {
	token, err := mustSigner(t).Sign(Claims{
		Subject:   "alice",
		IssuedAt:  time.Unix(1600000000, 0),
		ExpiresAt: time.Unix(1600003600, 0),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if token != goldenHS256 {
		t.Fatalf("Sign mismatch:\n got %s\nwant %s", token, goldenHS256)
	}

	claims, err := mustVerifier(t, WithNow(fixedClock(1600003599))).Verify(goldenHS256)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "alice" {
		t.Fatalf("Subject = %q, want alice", claims.Subject)
	}
	if !claims.ExpiresAt.Equal(time.Unix(1600003600, 0).UTC()) {
		t.Fatalf("ExpiresAt = %v, want unix 1600003600", claims.ExpiresAt)
	}

	if _, err := mustVerifier(t, WithNow(fixedClock(1600003601))).Verify(goldenHS256); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Verify past expiry: err = %v, want ErrTokenExpired", err)
	}
}

func TestEdDSARFC8037Vector(t *testing.T) {
	// RFC 8037, Appendix A.1/A.4: the Ed25519 key pair and signing example.
	seed, err := b64decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	alg, err := newEdDSASignAlg(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("newEdDSASignAlg: %v", err)
	}

	wantPub, _ := b64decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if !bytes.Equal(alg.pub, wantPub) {
		t.Fatalf("derived public key mismatch:\n got %x\nwant %x", alg.pub, wantPub)
	}

	const signingInput = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	got, err := alg.sign([]byte(signingInput))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wantSig, _ := b64decode("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6" +
		"dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg")
	if !bytes.Equal(got, wantSig) {
		t.Fatalf("Ed25519 signature mismatch:\n got %x\nwant %x", got, wantSig)
	}
	if err := alg.verify([]byte(signingInput), got); err != nil {
		t.Fatalf("verify: %v", err)
	}

	tampered := []byte(signingInput)
	tampered[len(tampered)-1] ^= 0x01
	if err := alg.verify(tampered, got); !errors.Is(err, ErrTokenBadSignature) {
		t.Fatalf("verify tampered input: err = %v, want ErrTokenBadSignature", err)
	}
}

func TestEdDSAPublicAPIRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewSignerEdDSA(priv, WithTTL(time.Hour), WithNow(fixedClock(100)))
	if err != nil {
		t.Fatalf("NewSignerEdDSA: %v", err)
	}
	v, err := NewVerifierEdDSA(pub, WithNow(fixedClock(100)))
	if err != nil {
		t.Fatalf("NewVerifierEdDSA: %v", err)
	}

	token, err := s.Sign(Claims{Subject: "bob"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "bob" {
		t.Fatalf("Subject = %q, want bob", claims.Subject)
	}
	if !claims.ExpiresAt.Equal(time.Unix(3700, 0).UTC()) {
		t.Fatalf("ExpiresAt = %v, want unix 3700 (iat 100 + 1h)", claims.ExpiresAt)
	}

	other, _, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	wrong, err := NewVerifierEdDSA(other)
	if err != nil {
		t.Fatalf("NewVerifierEdDSA: %v", err)
	}
	if _, err := wrong.Verify(token); !errors.Is(err, ErrTokenBadSignature) {
		t.Fatalf("verify with wrong public key: err = %v, want ErrTokenBadSignature", err)
	}
}

func TestSignVerifyRoundTripWithExtra(t *testing.T) {
	extra := map[string]any{
		"org":     "acme",
		"attempt": json.Number("3"),
		"active":  false,
		"tags":    []any{"a", "b"},
		"nested":  map[string]any{"x": json.Number("1.5")},
	}
	claims := Claims{
		Subject:   "bob",
		Issuer:    "login",
		Audience:  Audience{"api", "dashboard"},
		ID:        "jti-1",
		IssuedAt:  time.Unix(100, 0),
		ExpiresAt: time.Unix(2000, 0),
		NotBefore: time.Unix(100, 0),
		Extra:     extra,
	}

	edSigner, edVerifier := mustEdDSAPair(t)
	cases := []struct {
		name     string
		signer   *Signer
		verifier *Verifier
	}{
		{"HS256", mustSigner(t), mustVerifier(t, WithNow(fixedClock(150)))},
		{"EdDSA", edSigner, edVerifier},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := tc.signer.Sign(claims)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			// Multi-audience marshals as a JSON array.
			payload, _ := b64decode(strings.Split(token, ".")[1])
			if !strings.Contains(string(payload), `"aud":["api","dashboard"]`) {
				t.Fatalf("payload audience = %s, want JSON array", payload)
			}

			got, err := tc.verifier.Verify(token)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got.Subject != claims.Subject || got.Issuer != claims.Issuer ||
				got.ID != claims.ID || !got.ExpiresAt.Equal(claims.ExpiresAt.UTC()) ||
				!got.IssuedAt.Equal(claims.IssuedAt.UTC()) || !got.NotBefore.Equal(claims.NotBefore.UTC()) {
				t.Fatalf("registered claims round-trip mismatch: %+v", got)
			}
			if !reflect.DeepEqual(got.Audience, claims.Audience) {
				t.Fatalf("Audience = %v, want %v", got.Audience, claims.Audience)
			}
			if !reflect.DeepEqual(got.Extra, extra) {
				t.Fatalf("Extra =\n %#v\nwant\n %#v", got.Extra, extra)
			}
		})
	}
}

// mustEdDSAPair returns a signer and verifier sharing one freshly generated
// Ed25519 key pair.
func mustEdDSAPair(t *testing.T) (*Signer, *Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewSignerEdDSA(priv)
	if err != nil {
		t.Fatalf("NewSignerEdDSA: %v", err)
	}
	v, err := NewVerifierEdDSA(pub, WithNow(fixedClock(150)))
	if err != nil {
		t.Fatalf("NewVerifierEdDSA: %v", err)
	}
	return s, v
}

func TestSingleAudienceMarshalsAsString(t *testing.T) {
	token, err := mustSigner(t).Sign(Claims{
		Subject:   "bob",
		Audience:  Audience{"api"},
		IssuedAt:  time.Unix(1, 0),
		ExpiresAt: time.Unix(2, 0),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	payload, _ := b64decode(strings.Split(token, ".")[1])
	if !strings.Contains(string(payload), `"aud":"api"`) {
		t.Fatalf("payload = %s, want single-string aud", payload)
	}

	v := mustVerifier(t, WithExpectedAudience("api"), WithNow(fixedClock(1)))
	if _, err := v.Verify(token); err != nil {
		t.Fatalf("Verify with expected audience: %v", err)
	}
}

func TestRejectsForeignAlgorithm(t *testing.T) {
	hsToken, err := mustSigner(t).Sign(Claims{
		Subject: "bob", IssuedAt: time.Unix(1, 0), ExpiresAt: time.Unix(2, 0),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	edVerifier, err := NewVerifierEdDSA(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatalf("NewVerifierEdDSA: %v", err)
	}
	if _, err := edVerifier.Verify(hsToken); !errors.Is(err, ErrAlgMismatch) {
		t.Fatalf("HS256 token into EdDSA verifier: err = %v, want ErrAlgMismatch", err)
	}

	// An EdDSA-signed token verified as HS256 must also fail. Build it by
	// hand so the HS256 verifier sees a valid EdDSA token shape.
	edAlg, err := newEdDSASignAlg(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("newEdDSASignAlg: %v", err)
	}
	input := b64encode(edAlg.header()) + "." + b64encode([]byte(`{"sub":"bob","exp":9999999999}`))
	sig, _ := edAlg.sign([]byte(input))
	if _, err := mustVerifier(t).Verify(input + "." + b64encode(sig)); !errors.Is(err, ErrAlgMismatch) {
		t.Fatalf("EdDSA token into HS256 verifier: err = %v, want ErrAlgMismatch", err)
	}
}

func TestRejectsNoneAlgorithm(t *testing.T) {
	// alg "none" with a non-empty signature segment: rejected by the alg pin.
	noneToken := b64encode([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		b64encode([]byte(`{"sub":"evil","exp":9999999999}`)) + "." +
		b64encode([]byte("forged"))
	if _, err := mustVerifier(t).Verify(noneToken); !errors.Is(err, ErrAlgMismatch) {
		t.Fatalf("alg none: err = %v, want ErrAlgMismatch", err)
	}

	// alg "none" with the conventional empty signature segment: rejected as
	// malformed before the alg check even runs.
	emptySig := b64encode([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		b64encode([]byte(`{"sub":"evil","exp":9999999999}`)) + "."
	if _, err := mustVerifier(t).Verify(emptySig); !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("alg none with empty signature: err = %v, want ErrTokenMalformed", err)
	}
}

func TestRejectsBadTypAndCrit(t *testing.T) {
	clock := WithNow(fixedClock(1600003599))

	cases := []struct {
		name   string
		header string
		want   error
	}{
		{"typ JWE", `{"alg":"HS256","typ":"JWE"}`, ErrUnexpectedTyp},
		{"typ with media prefix accepted", `{"alg":"HS256","typ":"application/JWT"}`, nil},
		{"typ lowercase accepted", `{"alg":"HS256","typ":"jwt"}`, nil},
		{"crit extension", `{"alg":"HS256","typ":"JWT","crit":["b64"]}`, ErrUnsupportedCrit},
		{"no alg", `{"typ":"JWT"}`, ErrAlgMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVerifierHS256([]byte(testSecret), clock)
			if err != nil {
				t.Fatalf("NewVerifierHS256: %v", err)
			}
			_, got := v.Verify(craftToken(t, tc.header, goldenPayload))
			if tc.want == nil {
				if got != nil {
					t.Fatalf("Verify: unexpected error %v", got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("Verify: err = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTamperDetection(t *testing.T) {
	token, err := mustSigner(t).Sign(Claims{
		Subject: "bob", IssuedAt: time.Unix(1, 0), ExpiresAt: time.Unix(9999999999, 0),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	v := mustVerifier(t, WithNow(fixedClock(10)))

	// Re-signed payload with a forged subject keeps the original signature.
	parts := strings.Split(token, ".")
	forged := parts[0] + "." + b64encode([]byte(`{"sub":"evil","exp":9999999999}`)) + "." + parts[2]
	if _, err := v.Verify(forged); !errors.Is(err, ErrTokenBadSignature) {
		t.Fatalf("forged payload: err = %v, want ErrTokenBadSignature", err)
	}

	// Flipping one signature bit must fail.
	sig, _ := b64decode(parts[2])
	sig[0] ^= 0x01
	flipped := parts[0] + "." + parts[1] + "." + b64encode(sig)
	if _, err := v.Verify(flipped); !errors.Is(err, ErrTokenBadSignature) {
		t.Fatalf("flipped signature: err = %v, want ErrTokenBadSignature", err)
	}

	// A different secret must fail.
	other, err := NewVerifierHS256([]byte("fedcba9876543210fedcba9876543210fedcba9876543210"))
	if err != nil {
		t.Fatalf("NewVerifierHS256: %v", err)
	}
	if _, err := other.Verify(token); !errors.Is(err, ErrTokenBadSignature) {
		t.Fatalf("wrong secret: err = %v, want ErrTokenBadSignature", err)
	}
}

func TestClaimValidation(t *testing.T) {
	base := Claims{Subject: "bob", IssuedAt: time.Unix(1000, 0), ExpiresAt: time.Unix(2000, 0)}

	cases := []struct {
		name     string
		claims   func() Claims
		verifier []Option
		want     error
	}{
		{"expired", func() Claims { return base }, []Option{WithNow(fixedClock(2001))}, ErrTokenExpired},
		{"expired within leeway", func() Claims { return base },
			[]Option{WithNow(fixedClock(2001)), WithLeeway(10 * time.Second)}, nil},
		{"exp boundary valid", func() Claims { return base }, []Option{WithNow(fixedClock(2000))}, nil},
		{"nbf future", func() Claims { c := base; c.NotBefore = time.Unix(1500, 0); return c },
			[]Option{WithNow(fixedClock(1499))}, ErrTokenNotYetValid},
		{"nbf within leeway", func() Claims { c := base; c.NotBefore = time.Unix(1500, 0); return c },
			[]Option{WithNow(fixedClock(1499)), WithLeeway(time.Minute)}, nil},
		{"iat future", func() Claims { c := base; c.IssuedAt = time.Unix(1500, 0); return c },
			[]Option{WithNow(fixedClock(1499))}, ErrTokenIssuedInFuture},
		{"iat boundary valid", func() Claims { return base }, []Option{WithNow(fixedClock(1000))}, nil},
		{"issuer mismatch", func() Claims { c := base; c.Issuer = "rogue"; return c },
			[]Option{WithNow(fixedClock(1500)), WithExpectedIssuer("login")}, ErrIssuerMismatch},
		{"issuer match", func() Claims { c := base; c.Issuer = "login"; return c },
			[]Option{WithNow(fixedClock(1500)), WithExpectedIssuer("login")}, nil},
		{"audience mismatch", func() Claims { c := base; c.Audience = Audience{"api"}; return c },
			[]Option{WithNow(fixedClock(1500)), WithExpectedAudience("web")}, ErrAudienceMismatch},
		{"audience contained", func() Claims { c := base; c.Audience = Audience{"api", "web"}; return c },
			[]Option{WithNow(fixedClock(1500)), WithExpectedAudience("web")}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := mustSigner(t).Sign(tc.claims())
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			v, err := NewVerifierHS256([]byte(testSecret), tc.verifier...)
			if err != nil {
				t.Fatalf("NewVerifierHS256: %v", err)
			}
			_, got := v.Verify(token)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("Verify: unexpected error %v", got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("Verify: err = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMalformedTokens(t *testing.T) {
	v := mustVerifier(t)

	cases := []string{
		"",
		"not-a-token",
		"a.b",
		"a.b.c.d",
		".eyJhIjoxfQ." + b64encode([]byte("sig")),
		b64encode([]byte(`{"alg":"HS256"}`)) + "." + "." + b64encode([]byte("sig")),
		b64encode([]byte(`{"alg":"HS256"}`)) + "." + b64encode([]byte(`{"sub":"a"}`)) + ".",
		"!!!.@@@.###",
		// Invalid base64 characters.
		"***." + b64encode([]byte(`{}`)) + "." + b64encode([]byte("sig")),
	}
	for _, token := range cases {
		if _, err := v.Verify(token); !errors.Is(err, ErrTokenMalformed) {
			name := token
			if len(name) > 40 {
				name = name[:40] + "..."
			}
			t.Errorf("Verify(%q): err = %v, want ErrTokenMalformed", name, err)
		}
	}

	// Properly signed tokens whose payload fails to parse as claims.
	badPayloads := []string{
		`{"alg":"HS256"`,       // not JSON (header)
		"not-json",             // not JSON (payload)
		`{"sub":"a"} trailing`, // trailing data
		`{"sub":["a"]}`,        // sub must be a string
		`{"exp":"2000"}`,       // exp must be a numeric date
		`{"exp":1.5}`,          // exp must be a whole number
		`{"aud":42}`,           // aud must be string or array
		`123`,                  // payload must be an object
	}
	for _, payload := range badPayloads {
		if _, err := v.Verify(craftToken(t, `{"alg":"HS256","typ":"JWT"}`, payload)); !errors.Is(err, ErrTokenMalformed) {
			t.Errorf("Verify(payload %q): err = %v, want ErrTokenMalformed", payload, err)
		}
	}

	// base64 padding is not part of the compact JWS alphabet.
	padded := craftToken(t, `{"alg":"HS256","typ":"JWT"}`, goldenPayload)
	if _, err := v.Verify(padded + "="); !errors.Is(err, ErrTokenMalformed) {
		t.Fatalf("padded token: err = %v, want ErrTokenMalformed", err)
	}
}

func TestSignRequiresExpiration(t *testing.T) {
	if _, err := mustSigner(t).Sign(Claims{Subject: "bob"}); !errors.Is(err, ErrMissingExpiration) {
		t.Fatalf("Sign without exp/TTL: err = %v, want ErrMissingExpiration", err)
	}

	s := mustSigner(t, WithTTL(15*time.Minute), WithNow(fixedClock(1000)))
	token, err := s.Sign(Claims{Subject: "bob"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	payload, _ := b64decode(strings.Split(token, ".")[1])
	if !strings.Contains(string(payload), `"exp":1900`) {
		t.Fatalf("payload = %s, want exp = iat + TTL = 1900", payload)
	}

	// An explicit ExpiresAt wins over the configured TTL.
	token, err = s.Sign(Claims{Subject: "bob", ExpiresAt: time.Unix(5000, 0)})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	payload, _ = b64decode(strings.Split(token, ".")[1])
	if !strings.Contains(string(payload), `"exp":5000`) {
		t.Fatalf("payload = %s, want explicit exp preserved", payload)
	}
}

func TestSignerDefaults(t *testing.T) {
	s := mustSigner(t, WithIssuer("login"), WithAudience("api"), WithNow(fixedClock(1000)), WithTTL(time.Minute))

	token, err := s.Sign(Claims{Subject: "bob"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	payload, _ := b64decode(strings.Split(token, ".")[1])
	for _, want := range []string{`"iss":"login"`, `"aud":"api"`, `"iat":1000`, `"exp":1060`} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("payload = %s, want it to contain %s", payload, want)
		}
	}

	// Explicit values are never overwritten.
	token, err = s.Sign(Claims{
		Subject: "bob", Issuer: "other", Audience: Audience{"other"},
		IssuedAt: time.Unix(1000, 0), ExpiresAt: time.Unix(2000, 0),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	payload, _ = b64decode(strings.Split(token, ".")[1])
	if strings.Contains(string(payload), "login") || strings.Contains(string(payload), `"api"`) {
		t.Fatalf("payload = %s, explicit iss/aud must win", payload)
	}
}

func TestSignerRejectsReservedExtraClaims(t *testing.T) {
	_, err := mustSigner(t).Sign(Claims{
		Subject:   "bob",
		IssuedAt:  time.Unix(1, 0),
		ExpiresAt: time.Unix(2, 0),
		Extra:     map[string]any{"exp": 1},
	})
	if !errors.Is(err, ErrReservedClaim) {
		t.Fatalf("Sign: err = %v, want ErrReservedClaim", err)
	}
}

func TestSigningIsDeterministic(t *testing.T) {
	s := mustSigner(t, WithNow(fixedClock(1000)), WithTTL(time.Minute))
	claims := Claims{Subject: "bob"}
	a, err := s.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	b, err := s.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if a != b {
		t.Fatalf("same claims must sign to the same token:\n%s\n%s", a, b)
	}
}

func TestInvalidKeys(t *testing.T) {
	if _, err := NewSignerHS256([]byte("short")); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewSignerHS256 short key: err = %v, want ErrInvalidKey", err)
	}
	if _, err := NewVerifierHS256(make([]byte, 31)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewVerifierHS256 31-byte key: err = %v, want ErrInvalidKey", err)
	}
	if _, err := NewSignerHS256(make([]byte, 32)); err != nil {
		t.Fatalf("NewSignerHS256 32-byte key: %v", err)
	}
	if _, err := NewSignerEdDSA(make([]byte, ed25519.PublicKeySize)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewSignerEdDSA with public-size key: err = %v, want ErrInvalidKey", err)
	}
	if _, err := NewSignerEdDSA(nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewSignerEdDSA nil key: err = %v, want ErrInvalidKey", err)
	}
	if _, err := NewVerifierEdDSA(make([]byte, ed25519.PrivateKeySize)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewVerifierEdDSA with private-size key: err = %v, want ErrInvalidKey", err)
	}
}

func TestAudienceJSON(t *testing.T) {
	cases := []struct {
		aud  Audience
		json string
	}{
		{nil, "null"},
		{Audience{"a"}, `"a"`},
		{Audience{"a", "b"}, `["a","b"]`},
	}
	for _, tc := range cases {
		got, err := json.Marshal(tc.aud)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", tc.aud, err)
		}
		if string(got) != tc.json {
			t.Fatalf("Marshal(%v) = %s, want %s", tc.aud, got, tc.json)
		}
	}

	var a Audience
	if err := json.Unmarshal([]byte(`"a"`), &a); err != nil || len(a) != 1 || a[0] != "a" {
		t.Fatalf("Unmarshal string: a = %v, err = %v", a, err)
	}
	if err := json.Unmarshal([]byte(`["a","b"]`), &a); err != nil || len(a) != 2 {
		t.Fatalf("Unmarshal array: a = %v, err = %v", a, err)
	}
	if !a.Contains("a") || a.Contains("z") {
		t.Fatalf("Contains misbehaves for %v", a)
	}
	if err := json.Unmarshal([]byte(`null`), &a); err != nil || a != nil {
		t.Fatalf("Unmarshal null: a = %v, err = %v", a, err)
	}
	if err := json.Unmarshal([]byte(`42`), &a); err == nil {
		t.Fatal("Unmarshal number: expected error")
	}
}

func TestClaimsUnmarshalKeepsUnknownClaims(t *testing.T) {
	var c Claims
	raw := `{"sub":"bob","iss":"login","iat":1600000000,"exp":1600003600,` +
		`"jti":"x","nbf":1600000000,"team":"core","level":3,"flags":[true,null,1.5]}`
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if c.Subject != "bob" || c.Issuer != "login" || c.ID != "x" {
		t.Fatalf("claims = %+v", c)
	}
	if !c.ExpiresAt.Equal(time.Unix(1600003600, 0).UTC()) {
		t.Fatalf("ExpiresAt = %v", c.ExpiresAt)
	}
	want := map[string]any{"team": "core", "level": json.Number("3"),
		"flags": []any{true, nil, json.Number("1.5")}}
	if !reflect.DeepEqual(c.Extra, want) {
		t.Fatalf("Extra = %#v, want %#v", c.Extra, want)
	}

	// The Extra of a parsed token re-encodes losslessly.
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var again Claims
	if err := json.Unmarshal(data, &again); err != nil {
		t.Fatalf("re-Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(again, c) {
		t.Fatalf("round-trip mismatch:\n%#v\n%#v", again, c)
	}
}
