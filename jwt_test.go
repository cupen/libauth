package libauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// jwtIdentityFunc is the bearer-token glue tests attach to the middleware.
// The same shape — extract the bearer, verify, return sub — is what
// production code wires up (see _examples/jwtauth).
func jwtIdentityFunc(v *jwt.Verifier) IdentityFunc {
	return func(r *http.Request) (UserID, error) {
		h := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
			return "", errors.New("missing bearer token")
		}
		token := strings.TrimSpace(h[len(prefix):])
		if token == "" {
			return "", errors.New("missing bearer token")
		}
		claims, err := v.Verify(token)
		if err != nil {
			return "", err
		}
		if claims.Subject == "" {
			return "", errors.New("token has no sub claim")
		}
		return UserID(claims.Subject), nil
	}
}

func TestJWTIdentityExtraction(t *testing.T) {
	v := newTestVerifier(t)
	now := time.Now()
	identity := jwtIdentityFunc(v)

	cases := []struct {
		name    string
		auth    string
		wantID  string
		wantErr error
	}{
		{"valid bearer", "Bearer " + signToken(t, "bob", now, now.Add(time.Hour)), "bob", nil},
		{"lowercase scheme", "bearer " + signToken(t, "bob", now, now.Add(time.Hour)), "bob", nil},
		{"extra spaces", "Bearer   " + signToken(t, "bob", now, now.Add(time.Hour)) + "  ", "bob", nil},
		{"missing header", "", "", errMissingBearer},
		{"wrong scheme", "Basic dXNlcjpwYXNz", "", errMissingBearer},
		{"scheme only", "Bearer", "", errMissingBearer},
		{"empty token", "Bearer   ", "", errMissingBearer},
		{"expired token", "Bearer " + signToken(t, "bob", now.Add(-2*time.Hour), now.Add(-time.Hour)), "", jwt.ErrTokenExpired},
		{"forged token", "Bearer " + flipLastChar(signToken(t, "bob", now, now.Add(time.Hour))), "", jwt.ErrTokenBadSignature},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			id, err := identity(req)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) && err.Error() != tc.wantErr.Error() {
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

func TestJWTSignWithoutSubjectRejected(t *testing.T) {
	s, err := jwt.NewSignerHS256([]byte(testJWTSecret), jwt.WithTTL(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Sign must refuse to issue a token with no Subject: libauth uses sub
	// as the user ID, so a token without it has nothing downstream can
	// authenticate against.
	if _, err := s.Sign(jwt.Claims{}); !errors.Is(err, jwt.ErrMissingSubject) {
		t.Fatalf("Sign(empty): err = %v, want ErrMissingSubject", err)
	}
}

func TestMiddlewareWithJWTIdentity(t *testing.T) {
	e := newTestEnforcer(t)
	mw, err := NewMiddleware(e, jwtIdentityFunc(newTestVerifier(t)))
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

// errMissingBearer is the failure the inline identity returns when the
// Authorization header is missing or doesn't carry a Bearer token. We
// compare against this sentinel by string to keep the test focused on the
// outcome (401 path) rather than the specific error value, which each
// caller is free to choose.
var errMissingBearer = errors.New("missing bearer token")

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