// Command jwtauth demonstrates libauth with JWT bearer authentication:
// POST /login issues a short-lived HS256 token naming the user (sub), and
// every protected route verifies that token through a small IdentityFunc
// that calls verifier.Verify and reads the sub claim.
//
// Roles and permissions live server-side in the Enforcer, so changing a
// user's roles takes effect on their next request — tokens stay valid, the
// authority behind them does not.
//
// The demo accepts any known username without a password; wire a real
// credential check into the login handler in production.
//
// Seeded accounts:
//
//	alice — admin           (all permissions via "*")
//	bob   — editor + viewer (multi-role union)
//	carol — viewer          (read only)
//
//	go run ./_examples/jwtauth
//	TOKEN=$(curl -s -X POST -d '{"username":"bob"}' localhost:8081/login | sed -E 's/.*"token":"([^"]+)".*/\1/')
//	curl -H "Authorization: Bearer $TOKEN" localhost:8081/whoami
//	curl -H "Authorization: Bearer $TOKEN" localhost:8081/articles
//	curl -X POST -H "Authorization: Bearer $TOKEN" -d '{"title":"hi"}' localhost:8081/articles
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	libauth "github.com/cupen/libauth"
	"github.com/cupen/libauth/jwt"
)

const addr = "localhost:8081"

const issuer = "libauth-jwtauth-demo"

const ttl = 15 * time.Minute

// secret must be at least 32 bytes for HS256; load it from configuration in
// production instead of hardcoding it.
var secret = []byte("demo-secret-0123456789abcdef-demo-secret-32")

func main() {
	m := seed()

	signer, err := jwt.NewSignerHS256(secret, jwt.WithTTL(ttl), jwt.WithIssuer(issuer))
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := jwt.NewVerifierHS256(secret, jwt.WithExpectedIssuer(issuer))
	if err != nil {
		log.Fatal(err)
	}

	mw, err := libauth.NewMiddleware(m, jwtIdentity(verifier))
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /login", loginHandler(m, signer))
	mux.Handle("GET /whoami", mw.Require(perm("whoami:read"))(http.HandlerFunc(whoami)))
	mux.Handle("GET /articles", mw.Require(perm("article:read"))(http.HandlerFunc(listArticles)))
	mux.Handle("POST /articles", mw.Require(perm("article:create"))(http.HandlerFunc(createArticle)))

	log.Printf("listening on http://%s (identify via Authorization: Bearer <token>)", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// jwtIdentity builds the IdentityFunc the middleware uses to name the
// calling user. Extracts the bearer token from the Authorization header,
// verifies it, and returns the sub claim. Verification errors (malformed,
// bad signature, expired, missing subject) all surface as 401 through the
// middleware — handlers never see an unauthenticated request.
func jwtIdentity(v *jwt.Verifier) libauth.IdentityFunc {
	return func(r *http.Request) (libauth.UserID, error) {
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
		return libauth.UserID(claims.Subject), nil
	}
}

// loginHandler checks the username (no password in this demo) and issues a
// token whose sub claim is the user ID.
func loginHandler(m *libauth.Enforcer, signer *jwt.Signer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username required"})
			return
		}
		if _, err := m.GetUser(in.Username); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unknown user"})
			return
		}
		token, err := signer.Sign(jwt.Claims{Subject: in.Username})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"token_type": "Bearer",
			"token":      token,
			"expires_in": int(ttl.Seconds()),
		})
	}
}

func whoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": libauth.UserFromContext(r.Context())})
}

type article struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
}

var (
	mu       sync.Mutex
	nextID   = 1
	articles = map[int]article{}
)

func listArticles(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	out := make([]article, 0, len(articles))
	for _, a := range articles {
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, out)
}

func createArticle(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	mu.Lock()
	defer mu.Unlock()
	a := article{ID: nextID, Title: in.Title}
	nextID++
	articles[a.ID] = a
	writeJSON(w, http.StatusCreated, a)
}

func seed() *libauth.Enforcer {
	m := libauth.New()

	for _, r := range []struct {
		name        string
		permissions []libauth.Permission
		parent      libauth.RoleName
	}{
		{"admin", []libauth.Permission{{Resource: "*"}}, ""},
		{"editor", []libauth.Permission{
			{Resource: "article", Action: "create"},
			{Resource: "article", Action: "edit"},
			{Resource: "article", Action: "read"},
			{Resource: "whoami", Action: "read"},
		}, ""},
		{"viewer", []libauth.Permission{
			{Resource: "article", Action: "read"},
			{Resource: "whoami", Action: "read"},
		}, ""},
	} {
		if err := m.CreateRole(r.name, r.permissions, r.parent); err != nil {
			log.Fatal(err)
		}
	}

	for id, roles := range map[string][]libauth.RoleName{
		"alice": {"admin"},
		"bob":   {"editor", "viewer"},
		"carol": {"viewer"},
	} {
		if err := m.CreateUser(id, roles...); err != nil {
			log.Fatal(err)
		}
	}
	return m
}

func perm(s string) libauth.Permission {
	p, err := libauth.ParsePermission(s)
	if err != nil {
		panic(err)
	}
	return p
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
