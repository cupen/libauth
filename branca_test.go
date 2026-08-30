package libauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cupen/libauth/branca"
)

const testBrancaKey = "0123456789abcdef0123456789abcdef" // 32 bytes

// bearerPayload is the identity payload the demo middleware flow carries:
// a JSON object with a string "sub" member.
type bearerPayload struct {
	Sub string `json:"sub"`
}

func (p bearerPayload) MarshalBinary() ([]byte, error) { return json.Marshal(p) }

func (p *bearerPayload) UnmarshalBinary(raw []byte) error { return json.Unmarshal(raw, p) }

func TestBearerIdentityWithBranca(t *testing.T) {
	e := newTestEnforcer(t)
	b, err := branca.New([]byte(testBrancaKey), branca.WithTTL(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	mw, err := NewMiddleware(e, BearerIdentity(b)) // *branca.Branca satisfies BearerVerifier
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

	bob, err := b.Encode(bearerPayload{Sub: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	carol, err := b.Encode(bearerPayload{Sub: "carol"})
	if err != nil {
		t.Fatal(err)
	}

	if rec := req(bob); rec.Code != http.StatusOK || identified != "bob" {
		t.Errorf("bob token: code=%d identified=%q", rec.Code, identified)
	}
	if rec := req(carol); rec.Code != http.StatusForbidden {
		t.Errorf("carol token: code=%d, want 403", rec.Code)
	}
	if rec := req(""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: code=%d, want 401", rec.Code)
	}

	// An expired token is rejected although it authenticates fine.
	expiredB, err := branca.New([]byte(testBrancaKey), branca.WithNow(fixedClock(time.Now().Add(-2*time.Hour).Unix())))
	if err != nil {
		t.Fatal(err)
	}
	expired, err := expiredB.Encode(bearerPayload{Sub: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := req(expired); rec.Code != http.StatusUnauthorized {
		t.Errorf("expired token: code=%d, want 401", rec.Code)
	}

	// A codec without a TTL must refuse bearer verification outright.
	noTTL, err := branca.New([]byte(testBrancaKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noTTL.VerifyBearer(bob); !errors.Is(err, branca.ErrMissingTTL) {
		t.Errorf("VerifyBearer without TTL: err = %v, want ErrMissingTTL", err)
	}

	// Garbage is 401, not 500.
	if rec := req("garbage-token"); rec.Code != http.StatusUnauthorized {
		t.Errorf("garbage token: code=%d, want 401", rec.Code)
	}
}

func fixedClock(unix int64) func() time.Time {
	return func() time.Time { return time.Unix(unix, 0) }
}
