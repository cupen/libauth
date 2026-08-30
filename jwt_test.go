package libauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cupen/libauth/jwt"
)

const testJWTSecret = "jwt-test-secret-0123456789abcdef-jwt-test-secret" // 48 bytes

func newTestVerifier(t *testing.T) *jwt.Verifier {
	t.Helper()
	v, err := jwt.NewVerifierHS256([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func signToken(t *testing.T, subject string, issued, expires time.Time) string {
	t.Helper()
	s, err := jwt.NewSignerHS256([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.Sign(jwt.Claims{Subject: subject, IssuedAt: issued, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestBearerIdentityExtraction(t *testing.T) {
	v := newTestVerifier(t)
	now := time.Now()
	identity := BearerIdentity(v)

	cases := []struct {
		name    string
		auth    string
		wantID  string
		wantErr error
	}{
		{"valid bearer", "Bearer " + signToken(t, "bob", now, now.Add(time.Hour)), "bob", nil},
		{"lowercase scheme", "bearer " + signToken(t, "bob", now, now.Add(time.Hour)), "bob", nil},
		{"extra spaces", "Bearer   " + signToken(t, "bob", now, now.Add(time.Hour)) + "  ", "bob", nil},
		{"missing header", "", "", ErrMissingBearerToken},
		{"wrong scheme", "Basic dXNlcjpwYXNz", "", ErrMissingBearerToken},
		{"scheme only", "Bearer", "", ErrMissingBearerToken},
		{"empty token", "Bearer   ", "", ErrMissingBearerToken},
		{"expired token", "Bearer " + signToken(t, "bob", now.Add(-2*time.Hour), now.Add(-time.Hour)), "", ErrTokenExpired},
		{"forged token", "Bearer " + flipLastChar(signToken(t, "bob", now, now.Add(time.Hour))), "", ErrTokenBadSignature},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			id, err := identity(req)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("identity: err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("identity: unexpected error %v", err)
			}
			if id != tc.wantID {
				t.Fatalf("identity = %q, want %q", id, tc.wantID)
			}
		})
	}
}

func TestBearerIdentityWithoutSubject(t *testing.T) {
	s, err := jwt.NewSignerHS256([]byte(testJWTSecret), jwt.WithTTL(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.Sign(jwt.Claims{}) // no sub: nothing to identify
	if err != nil {
		t.Fatal(err)
	}

	_, err = BearerIdentity(newTestVerifier(t))(bearerRequest(t, token))
	if !errors.Is(err, ErrTokenWithoutSubject) {
		t.Fatalf("identity: err = %v, want ErrTokenWithoutSubject", err)
	}
}

func TestMiddlewareWithBearerIdentity(t *testing.T) {
	e := newTestEnforcer(t)
	mw, err := NewMiddleware(e, BearerIdentity(newTestVerifier(t)))
	if err != nil {
		t.Fatal(err)
	}

	var identified string
	handler := mw.Require(perm("article:create"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identified = UserFromContext(r.Context()).ID
	}))

	req := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/articles", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec
	}

	now := time.Now()
	if rec := req(signToken(t, "bob", now, now.Add(time.Hour))); rec.Code != http.StatusOK || identified != "bob" {
		t.Errorf("bob token: code=%d identified=%q", rec.Code, identified)
	}
	if rec := req(signToken(t, "carol", now, now.Add(time.Hour))); rec.Code != http.StatusForbidden {
		t.Errorf("carol token: code=%d, want 403", rec.Code)
	}
	if rec := req(""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: code=%d, want 401", rec.Code)
	}
	if rec := req(signToken(t, "ghost", now, now.Add(time.Hour))); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown user token: code=%d, want 401", rec.Code)
	}
	if rec := req("not-a-jwt"); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: code=%d, want 401", rec.Code)
	}

	// Permissions resolve server-side: revoking dave's role invalidates the
	// capability his still-valid token appears to grant.
	dave := signToken(t, "dave", now, now.Add(time.Hour))
	if rec := req(dave); rec.Code != http.StatusOK {
		t.Fatalf("dave (publisher inherits editor): code=%d", rec.Code)
	}
	if err := e.RevokeRole("dave", "publisher"); err != nil {
		t.Fatal(err)
	}
	if rec := req(dave); rec.Code != http.StatusForbidden {
		t.Errorf("dave after revocation: code=%d, want 403", rec.Code)
	}
}

func bearerRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// flipLastChar deterministically corrupts a token so its signature breaks.
func flipLastChar(s string) string {
	if s == "" {
		return s
	}
	replacement := byte('A')
	if s[len(s)-1] == 'A' {
		replacement = 'B'
	}
	return s[:len(s)-1] + string(replacement)
}
