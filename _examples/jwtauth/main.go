// Command jwtauth demonstrates JWT bearer authentication: POST /login issues
// an HS256 token whose sub is the user, and protected routes verify it.
// Any known username is accepted without a password; do not copy that.
//
//	go run ./_examples/jwtauth
//	TOKEN=$(curl -s -X POST -d '{"username":"bob"}' localhost:8081/login | sed -E 's/.*"token":"([^"]+)".*/\1/')
//	curl -H "Authorization: Bearer $TOKEN" localhost:8081/articles
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

// secret must be at least 32 bytes for HS256.
var secret = []byte("demo-secret-0123456789abcdef-demo-secret-32")

func main() {
	m := seed()

	auth, err := jwt.New(secret,
		jwt.WithTTL(ttl),
		jwt.WithIssuer(issuer),
		jwt.WithExpectedIssuer(issuer),
	)
	if err != nil {
		log.Fatal(err)
	}

	mw, err := libauth.NewMiddleware(m, jwtIdentity(auth))
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /login", loginHandler(m, auth))
	mux.Handle("GET /whoami", mw.Require(libauth.Perm("whoami", "read"))(http.HandlerFunc(whoami)))
	mux.Handle("GET /articles", mw.Require(libauth.Perm("article", "read"))(http.HandlerFunc(listArticles)))
	mux.Handle("POST /articles", mw.Require(libauth.Perm("article", "create"))(http.HandlerFunc(createArticle)))

	log.Printf("listening on http://%s (identify via Authorization: Bearer <token>)", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// jwtIdentity resolves the user from a Bearer token.
func jwtIdentity(auth *jwt.JWT) libauth.IdentityFunc {
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
		claims, err := auth.Decode(token)
		if err != nil {
			return "", err
		}
		return libauth.UserID(claims.Subject), nil
	}
}

// loginHandler issues a token whose sub claim is the username.
func loginHandler(m *libauth.Enforcer, auth *jwt.JWT) http.HandlerFunc {
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
		token, err := auth.Encode(jwt.Claims{Subject: in.Username})
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
		parent      libauth.RoleID
	}{
		{"admin", []libauth.Permission{libauth.Perm("*", "")}, ""},
		{"editor", []libauth.Permission{
			libauth.Perm("article", "create"),
			libauth.Perm("article", "edit"),
			libauth.Perm("article", "read"),
			libauth.Perm("whoami", "read"),
		}, ""},
		{"viewer", []libauth.Permission{
			libauth.Perm("article", "read"),
			libauth.Perm("whoami", "read"),
		}, ""},
	} {
		if err := m.CreateRole(r.name, r.permissions, r.parent); err != nil {
			log.Fatal(err)
		}
	}

	for id, roles := range map[string][]libauth.RoleID{
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
