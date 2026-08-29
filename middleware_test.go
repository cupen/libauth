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

func TestMiddlewareRequire(t *testing.T) {
	m := newTestManager(t)
	mw, err := NewMiddleware(m, HeaderIdentity(""))
	if err != nil {
		t.Fatal(err)
	}

	handler := mw.Require("article:create")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	m := newTestManager(t)
	mw, _ := NewMiddleware(m, nil) // nil identity -> default header

	all := mw.RequireAll("article:create", "article:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if rec := doReq(t, all, "bob"); rec.Code != http.StatusOK {
		t.Errorf("bob holds both: code=%d", rec.Code)
	}
	if rec := doReq(t, all, "carol"); rec.Code != http.StatusForbidden {
		t.Errorf("carol holds one: code=%d", rec.Code)
	}

	any := mw.RequireAny("article:publish", "article:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
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
	m := newTestManager(t)
	mw, _ := NewMiddleware(m, nil)

	handler := mw.RequireAny()(okHandler)
	// Misconfiguration must fail closed with 403 — never panic.
	if rec := doReq(t, handler, "bob"); rec.Code != http.StatusForbidden {
		t.Errorf("empty RequireAny should deny: code=%d", rec.Code)
	}
}

func TestMiddlewareRequireAllWithoutPermissions(t *testing.T) {
	m := newTestManager(t)
	mw, _ := NewMiddleware(m, nil)

	handler := mw.RequireAll()(okHandler)
	// Vacuously true: nothing is required, so everyone passes.
	if rec := doReq(t, handler, "carol"); rec.Code != http.StatusOK {
		t.Errorf("empty RequireAll should pass through: code=%d", rec.Code)
	}
}

func TestMiddlewareRequireRoleUnknownUser(t *testing.T) {
	m := newTestManager(t)
	mw, _ := NewMiddleware(m, nil)

	handler := mw.RequireRole("admin")(okHandler)
	if rec := doReq(t, handler, "ghost"); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown user should be rejected with 401: code=%d", rec.Code)
	}
}

func TestMiddlewareNewMiddlewareNilManager(t *testing.T) {
	if _, err := NewMiddleware(nil, nil); !errors.Is(err, ErrInvalidIdentityFunc) {
		t.Errorf("nil manager should be rejected, got %v", err)
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
	m := New(WithStore(&failingStore{NewMemoryStore()}))
	mw, _ := NewMiddleware(m, nil)

	handler := mw.Require("article:read")(okHandler)
	if rec := doReq(t, handler, "bob"); rec.Code != http.StatusInternalServerError {
		t.Errorf("store failure should surface as 500: code=%d", rec.Code)
	}
}

func TestMiddlewareCustomIdentityAndOnError(t *testing.T) {
	m := newTestManager(t)
	mw, _ := NewMiddleware(m, func(r *http.Request) (UserID, error) {
		return r.Header.Get("Authorization"), nil
	})
	called := false
	mw.OnError = func(w http.ResponseWriter, r *http.Request, status int, err error) {
		called = true
		w.WriteHeader(status)
	}

	handler := mw.Require("article:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
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
