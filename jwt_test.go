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

func newTestJWT(t *testing.T) *jwt.JWT {
	t.Helper()
	j, err := jwt.New([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func signToken(t *testing.T, subject string, issued, expires time.Time) string {
	t.Helper()
	j, err := jwt.New([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	token, err := j.Encode(jwt.Claims{Subject: subject, IssuedAt: issued, ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// jwtIdentityFunc extracts the bearer, verifies it and returns sub.
func jwtIdentityFunc(v *jwt.JWT) IdentityFunc {
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
		claims, err := v.Decode(token)
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
	v := newTestJWT(t)
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
		{"forged token", "Bearer " + corruptSignature(signToken(t, "bob", now, now.Add(time.Hour))), "", jwt.ErrTokenBadSignature},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			id, err := identity(req)
			if tc.wantErr != nil {
				if err == nil || (!errors.Is(err, tc.wantErr) && err.Error() != tc.wantErr.Error()) {
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
	j, err := jwt.New([]byte(testJWTSecret), jwt.WithTTL(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// sub is the user ID, so it is mandatory.
	if _, err := j.Encode(jwt.Claims{}); !errors.Is(err, jwt.ErrMissingSubject) {
		t.Fatalf("Sign(empty): err = %v, want ErrMissingSubject", err)
	}
}

func TestMiddlewareWithJWTIdentity(t *testing.T) {
	e := newTestEnforcer(t)
	mw, err := NewMiddleware(e, jwtIdentityFunc(newTestJWT(t)))
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

// errMissingBearer is returned by the inline identity; tests match it by
// string because each caller picks its own error value.
var errMissingBearer = errors.New("missing bearer token")

// corruptSignature changes the first signature byte. The final base64url
// character is not usable here: its trailing bits are ignored on decode.
func corruptSignature(s string) string {
	i := strings.LastIndexByte(s, '.')
	if i < 0 || i+2 > len(s) {
		return s
	}
	c := byte('A')
	if s[i+1] == 'A' {
		c = 'B'
	}
	return s[:i+1] + string(c) + s[i+2:]
}
