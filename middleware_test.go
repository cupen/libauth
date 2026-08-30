package libauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// perm turns a "resource:action" string into a Permission for tests.
func perm(s string) Permission {
	p, err := ParsePermission(s)
	if err != nil {
		panic(err)
	}
	return p
}

func doReq(t *testing.T, h http.Handler, user string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if user != "" {
		req.Header.Set("X-User-ID", user)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// newTestEnforcer builds a minimal RBAC world for the middleware tests.
func newTestEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e := New()

	if err := e.CreateRole("admin", []Permission{perm("*")}); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateRole("editor", []Permission{perm("article:create"), perm("article:edit"), perm("article:read")}); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateRole("viewer", []Permission{perm("article:read")}); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateRole("publisher", []Permission{perm("article:publish")}, "editor"); err != nil {
		t.Fatal(err)
	}

	users := map[string][]RoleName{
		"alice": {"admin"},
		"bob":   {"editor", "viewer"},
		"carol": {"viewer"},
		"dave":  {"publisher"},
	}
	for id, roles := range users {
		if err := e.CreateUser(id, roles...); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func TestMiddlewareRequire(t *testing.T) {
	e := newTestEnforcer(t)
	mw, err := NewMiddleware(e, HeaderIdentity(""))
	if err != nil {
		t.Fatal(err)
	}

	handler := mw.Require(perm("article:create"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromContext(r.Context())
		_, _ = w.Write([]byte("hello " + u.ID))
	}))

	if rec := doReq(t, handler, "bob"); rec.Code != http.StatusOK {
		t.Errorf("bob may create: code=%d body=%s", rec.Code, rec.Body)
	}
	if rec := doReq(t, handler, "carol"); rec.Code != http.StatusForbidden {
		t.Errorf("carol may not create: code=%d body=%s", rec.Code, rec.Body)
	}
	if rec := doReq(t, handler, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("missing identity: code=%d body=%s", rec.Code, rec.Body)
	}
	if rec := doReq(t, handler, "ghost"); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown user: code=%d body=%s", rec.Code, rec.Body)
	}
}

func TestMiddlewareRequireAllAnyRole(t *testing.T) {
	e := newTestEnforcer(t)
	mw, _ := NewMiddleware(e, nil)

	all := mw.RequireAll(perm("article:create"), perm("article:read"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if rec := doReq(t, all, "bob"); rec.Code != http.StatusOK {
		t.Errorf("bob holds both: code=%d", rec.Code)
	}
	if rec := doReq(t, all, "carol"); rec.Code != http.StatusForbidden {
		t.Errorf("carol holds one: code=%d", rec.Code)
	}

	any := mw.RequireAny(perm("article:publish"), perm("article:read"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if rec := doReq(t, any, "carol"); rec.Code != http.StatusOK {
		t.Errorf("carol holds read: code=%d", rec.Code)
	}

	role := mw.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if rec := doReq(t, role, "alice"); rec.Code != http.StatusOK {
		t.Errorf("alice is admin: code=%d", rec.Code)
	}
	if rec := doReq(t, role, "bob"); rec.Code != http.StatusForbidden {
		t.Errorf("bob is not admin: code=%d", rec.Code)
	}
}

func TestMiddlewareRequireAnyWithoutPermissions(t *testing.T) {
	e := newTestEnforcer(t)
	mw, _ := NewMiddleware(e, nil)

	handler := mw.RequireAny()(okHandler)
	// Misconfiguration must fail closed with 403 — never panic.
	if rec := doReq(t, handler, "bob"); rec.Code != http.StatusForbidden {
		t.Errorf("empty RequireAny should deny: code=%d", rec.Code)
	}
}

func TestMiddlewareRequireAllWithoutPermissions(t *testing.T) {
	e := newTestEnforcer(t)
	mw, _ := NewMiddleware(e, nil)

	handler := mw.RequireAll()(okHandler)
	// Vacuously true: nothing is required, so everyone passes.
	if rec := doReq(t, handler, "carol"); rec.Code != http.StatusOK {
		t.Errorf("empty RequireAll should pass through: code=%d", rec.Code)
	}
}

func TestMiddlewareRequireRoleUnknownUser(t *testing.T) {
	e := newTestEnforcer(t)
	mw, _ := NewMiddleware(e, nil)

	handler := mw.RequireRole("admin")(okHandler)
	if rec := doReq(t, handler, "ghost"); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown user should be rejected with 401: code=%d", rec.Code)
	}
}

func TestMiddlewareNewMiddlewareNilEnforcer(t *testing.T) {
	if _, err := NewMiddleware(nil, nil); !errors.Is(err, ErrInvalidIdentityFunc) {
		t.Errorf("nil enforcer should be rejected, got %v", err)
	}
}

// failingStore simulates a backend outage to exercise the 500 path.
type failingStore struct {
	*MemoryStore
}

func (f *failingStore) GetUser(id UserID) (*User, error) {
	return nil, errors.New("backend unavailable")
}

func TestMiddlewareInternalError(t *testing.T) {
	e := New(WithStore(&failingStore{NewMemoryStore()}))
	mw, _ := NewMiddleware(e, nil)

	handler := mw.Require(perm("article:read"))(okHandler)
	if rec := doReq(t, handler, "bob"); rec.Code != http.StatusInternalServerError {
		t.Errorf("store failure should surface as 500: code=%d", rec.Code)
	}
}

func TestMiddlewareCustomIdentityAndOnError(t *testing.T) {
	e := newTestEnforcer(t)
	mw, _ := NewMiddleware(e, func(r *http.Request) (UserID, error) {
		return r.Header.Get("Authorization"), nil
	})
	called := false
	mw.OnError = func(w http.ResponseWriter, r *http.Request, status int, err error) {
		called = true
		w.WriteHeader(status)
	}

	handler := mw.Require(perm("article:read"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "carol")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("carol may read: code=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || rec.Code != http.StatusUnauthorized {
		t.Errorf("custom on-error hook: called=%v code=%d", called, rec.Code)
	}
}
