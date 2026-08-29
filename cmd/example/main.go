// Command example demonstrates the libauth multi-role permission system with
// a small HTTP API.
//
// Identities are supplied via the X-User-ID header (see HeaderIdentity) — in
// production you would plug in JWT/session authentication instead.
//
// Seeded accounts:
//
//	alice — admin                       (all permissions via "*")
//	bob   — editor + viewer             (multi-role union)
//	carol — viewer                      (read only)
//	dave  — publisher (inherits editor) (role inheritance)
//
// Try:
//
//	go run ./cmd/example
//	curl -H "X-User-ID: alice" localhost:8080/articles          # 200
//	curl -X POST -H "X-User-ID: bob" localhost:8080/articles    # 201
//	curl -X POST -H "X-User-ID: carol" localhost:8080/articles  # 403
//	curl -H "X-User-ID: carol" localhost:8080/whoami            # effective permissions
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

	libauth "libauth"
)

type article struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
}

type server struct {
	mu       sync.Mutex
	nextID   int
	articles map[int]article
}

func main() {
	m := seed()

	mw, err := libauth.NewMiddleware(m, libauth.HeaderIdentity(""))
	if err != nil {
		log.Fatal(err)
	}
	s := &server{articles: map[int]article{}, nextID: 1}

	mux := http.NewServeMux()
	mux.Handle("GET /whoami", mw.Require("whoami:read")(http.HandlerFunc(s.whoami)))
	mux.Handle("GET /articles", mw.Require("article:read")(http.HandlerFunc(s.list)))
	mux.Handle("POST /articles", mw.Require("article:create")(http.HandlerFunc(s.create)))
	mux.Handle("DELETE /articles/{id}", mw.Require("article:delete")(http.HandlerFunc(s.remove)))
	// Multi-permission and role-based guards are also available:
	//   mux.Handle("POST /publish", mw.RequireAll("article:edit", "article:publish")(...))
	//   mux.Handle("GET /audit",    mw.RequireRole("admin")(...))

	addr := "localhost:8080"
	log.Printf("listening on http://%s (identify via X-User-ID header)", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// seed builds the demo RBAC world.
func seed() *libauth.Manager {
	m := libauth.New()

	// Roles.
	if err := m.CreateRole("admin", []libauth.Permission{"*"}); err != nil {
		log.Fatal(err)
	}
	if err := m.CreateRole("editor", []libauth.Permission{
		"article:create", "article:edit", "article:read", "whoami:read",
	}); err != nil {
		log.Fatal(err)
	}
	if err := m.CreateRole("viewer", []libauth.Permission{"article:read", "whoami:read"}); err != nil {
		log.Fatal(err)
	}
	// publisher inherits every editor permission.
	if err := m.CreateRole("publisher", []libauth.Permission{"article:publish"}, "editor"); err != nil {
		log.Fatal(err)
	}

	// Users, each possibly holding multiple roles.
	users := map[string][]libauth.RoleName{
		"alice": {"admin"},
		"bob":   {"editor", "viewer"},
		"carol": {"viewer"},
		"dave":  {"publisher"},
	}
	for id, roles := range users {
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

// whoami shows the caller's roles and effective permissions.
func (s *server) whoami(w http.ResponseWriter, r *http.Request) {
	u := libauth.UserFromContext(r.Context())
	if u == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "no user in context"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u})
}

func (s *server) list(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]article, 0, len(s.articles))
	for _, a := range s.articles {
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) create(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := article{ID: s.nextID, Title: in.Title}
	s.nextID++
	s.articles[a.ID] = a
	writeJSON(w, http.StatusCreated, a)
}

func (s *server) remove(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid article id"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.articles[id]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "article not found"})
		return
	}
	delete(s.articles, id)
	w.WriteHeader(http.StatusNoContent)
}
