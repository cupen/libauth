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
	if _, err := NewMiddleware(nil, nil); !errors.Is(err, ErrInvalidIdentityFunc) {
		t.Errorf("nil authorizer should be rejected, got %v", err)
	}
}

func TestNilIdentityDefaultsToHeader(t *testing.T) {
	mw, err := NewMiddleware(&stubAuthorizer{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mw.identity == nil {
		t.Fatal("nil identity must default to HeaderIdentity")
	}
	if _, err := mw.identity(httptest.NewRequest("GET", "/", nil)); err == nil {
		t.Error("default identity must reject requests without the header")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-User-ID", "u")
	if id, err := mw.identity(req); err != nil || id != "u" {
		t.Errorf("default identity should read X-User-ID, got %q %v", id, err)
	}
}

func TestContextRoundTrip(t *testing.T) {
	if UserFromContext(t.Context()) != nil {
		t.Error("empty context must yield nil user")
	}
	u := &model.User{ID: "u"}
	if got := UserFromContext(WithUser(t.Context(), u)); got != u {
		t.Errorf("WithUser/UserFromContext round trip failed: %+v", got)
	}
}
