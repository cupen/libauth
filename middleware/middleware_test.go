package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cupen/libauth/model"
)

// stubAuthorizer proves the guards decouple from *libauth.Manager: any
// Authorizer implementation works.
type stubAuthorizer struct {
	denied error
}

func (s *stubAuthorizer) Check(id model.UserID, required model.Permission) error {
	if s.denied != nil {
		return s.denied
	}
	return nil
}

func (s *stubAuthorizer) HasPermission(id model.UserID, required model.Permission) (bool, error) {
	return s.denied == nil, nil
}

func (s *stubAuthorizer) HasRole(id model.UserID, role model.RoleID) (bool, error) {
	return s.denied == nil, nil
}

func (s *stubAuthorizer) GetUser(id model.UserID) (*model.User, error) {
	return &model.User{ID: id, Roles: []model.RoleID{"stub"}}, nil
}

func TestGuardsWithCustomAuthorizer(t *testing.T) {
	allow := &stubAuthorizer{}
	mw, err := NewMiddleware(allow, func(r *http.Request) (model.UserID, error) { return "u", nil })
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	authorized := mw.Require(model.Permission{Resource: "any", Action: "thing"})(next)
	deniedMW := mw.RequireRole("nope")(next)

	rec := httptest.NewRecorder()
	authorized.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("custom authorizer granting access should pass the guard, got %d", rec.Code)
	}

	allow.denied = &model.PermissionDeniedError{UserID: "u", Required: model.Permission{Resource: "any", Action: "thing"}}
	rec = httptest.NewRecorder()
	deniedMW.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("custom authorizer denying access should yield 403, got %d", rec.Code)
	}
}

func TestNewMiddlewareNilAuthorizer(t *testing.T) {
	if _, err := NewMiddleware(nil, HeaderIdentity("")); !errors.Is(err, ErrNilAuthorizer) {
		t.Errorf("nil authorizer should be rejected, got %v", err)
	}
}

func TestNewMiddlewareNilIdentityRejected(t *testing.T) {
	if _, err := NewMiddleware(&stubAuthorizer{}, nil); !errors.Is(err, ErrNilIdentityFunc) {
		t.Errorf("nil identity must be rejected — no silent insecure default, got %v", err)
	}
}

func TestHeaderIdentity(t *testing.T) {
	identity := HeaderIdentity("")
	if _, err := identity(httptest.NewRequest("GET", "/", nil)); err == nil {
		t.Error("identity must reject requests without the header")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-User-ID", "u")
	if id, err := identity(req); err != nil || id != "u" {
		t.Errorf("identity should read X-User-ID, got %q %v", id, err)
	}
}

// TestWithOnError replaces the JSON error body with a custom renderer.
func TestWithOnError(t *testing.T) {
	var gotStatus int
	mw, err := NewMiddleware(&stubAuthorizer{denied: model.ErrPermissionDenied},
		HeaderIdentity(""),
		WithOnError(func(w http.ResponseWriter, r *http.Request, status int, err error) {
			gotStatus = status
			w.WriteHeader(status)
		}))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-User-ID", "u")
	rec := httptest.NewRecorder()
	mw.Require(model.Permission{Resource: "any", Action: "thing"})(okHandler).
		ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || gotStatus != http.StatusForbidden {
		t.Errorf("custom error handler: code=%d gotStatus=%d", rec.Code, gotStatus)
	}
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

func TestContextRoundTrip(t *testing.T) {
	if UserFromContext(t.Context()) != nil {
		t.Error("empty context must yield nil user")
	}
	u := &model.User{ID: "u"}
	if got := UserFromContext(WithUser(t.Context(), u)); got != u {
		t.Errorf("WithUser/UserFromContext round trip failed: %+v", got)
	}
}
