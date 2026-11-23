// Command example demonstrates libauth behind a small HTTP API, identifying
// callers by the X-User-ID header. See _examples/jwtauth for bearer tokens.
//
//	go run ./_examples/example01
//	curl -H "X-User-ID: alice" localhost:8080/articles          # 200
//	curl -X POST -H "X-User-ID: carol" localhost:8080/articles  # 403
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"

	libauth "github.com/cupen/libauth"
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
	mux.Handle("GET /whoami", mw.Require(libauth.Perm("whoami", "read"))(http.HandlerFunc(s.whoami)))
	mux.Handle("GET /articles", mw.Require(libauth.Perm("article", "read"))(http.HandlerFunc(s.list)))
	mux.Handle("POST /articles", mw.Require(libauth.Perm("article", "create"))(http.HandlerFunc(s.create)))
	mux.Handle("DELETE /articles/{id}", mw.Require(libauth.Perm("article", "delete"))(http.HandlerFunc(s.remove)))

	log.Printf("listening on http://localhost:8080 (identify via X-User-ID header)")
	log.Fatal(http.ListenAndServe("localhost:8080", mux))
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
		{"publisher", []libauth.Permission{
			libauth.Perm("article", "publish"),
		}, "editor"},
	} {
		if err := m.CreateRole(r.name, r.permissions, r.parent); err != nil {
			log.Fatal(err)
		}
	}

	for id, roles := range map[string][]libauth.RoleID{
		"alice": {"admin"},
		"bob":   {"editor", "viewer"},
		"carol": {"viewer"},
		"dave":  {"publisher"},
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
