English | [简体中文](README-zh.md)

# libauth

Multi-role access control for Go. A user holds several roles, a role inherits from one parent, and permissions are `resource:action` strings with wildcards. Zero-dependency core, pluggable `Store`, `net/http` middleware, plus JWT and Branca tokens.

## Features

- Multiple roles per user, single-parent inheritance, wildcard permissions (`article:*` / `*`) and direct grants.
- Pluggable `Store`; `MemoryStore` is the reference implementation.
- `net/http` middleware: `Require` / `RequireAll` / `RequireAny` / `RequireRole`.
- Tokens: `jwt` (HS256 / Ed25519, stdlib) and `branca` (XChaCha20-Poly1305).
- Zero third-party dependencies; safe for concurrent use; a warm `Check` is one map lookup with no allocations.

## Quick start

```go
m := libauth.New()

// Last argument is the parent role; "" for none.
m.CreateRole("editor",    []libauth.Permission{{"article", "create"}, {"article", "edit"}}, "")
m.CreateRole("viewer",    []libauth.Permission{{"article", "read"}}, "")
m.CreateRole("publisher", []libauth.Permission{{"article", "publish"}}, "editor") // inherits editor
m.CreateRole("admin",     []libauth.Permission{{"*", ""}}, "")                    // wildcard

m.CreateUser("bob", "editor", "viewer")
m.CreateUser("alice", "admin")

m.Check("bob",   libauth.Perm("article", "create")) // nil
m.Check("bob",   libauth.Perm("article", "delete")) // ErrPermissionDenied
m.Check("alice", libauth.Perm("article", "delete")) // nil

m.AssignRole("bob", "publisher")
m.Check("bob", libauth.Perm("article", "publish"))  // nil
```

## Permissions

`resource:action`; segments are open-ended (`tenant:article:read`). Actions are plain strings (`read`, `write`, `exec`, or anything else) and imply nothing: `write` does not grant `read`. Build one with `libauth.Perm("article", "read")`, or parse a string with `ParsePermission("article:read")`.

| Granted | Checked | Result |
|---|---|---|
| `article:create` | `article:create` | ✅ |
| `article:*` | `article:delete` | ✅ |
| `*` | anything | ✅ |
| `article:read` | `article:delete` | ❌ |
| `article:read` | `article:read:extra` | ❌ (segment count differs) |

## API

`Enforcer` (see [authz/authz.go](authz/authz.go)) is the RBAC layer over a `Store`.

- Users: `CreateUser` / `DeleteUser` / `GetUser` / `ListUsers`
- Roles: `CreateRole` / `UpdateRole` / `DeleteRole` / `GetRole` / `ListRoles` / `SetParent` / `RolesFor`
- Grants: `AssignRole` / `RevokeRole`; `GrantPermission` / `RevokePermission`; `GrantDirectPermission` / `RevokeDirectPermission`
- Checks: `Check` (returns an error), `HasPermission`, `HasRole` (direct roles only), `PermissionsFor` (effective set)
- Options passed to `libauth.New`: `WithStore`, `WithMaxDepth`, `WithCacheSize`, `WithCacheTTL`, `WithUnboundedCache`; the cache defaults to 10,000 users and a 24-hour idle TTL

Reads run concurrently; writes are serialized and visible once they return. The `Enforcer` must be the only writer to its `Store`.

`Store` ([store/store.go](store/store.go)) is the persistence contract; `MemoryStore` is the reference implementation. To use MySQL/Postgres, implement it and pass `libauth.WithStore(myStore)`.

### Memory

`MemoryStore` holds data; the `Enforcer` cache memoizes users lazily on first check, so registration adds no per-user index. A 100k-user store is ~13 MB; checking everyone with 10k cached adds ~16 MB. Past ~100k users use an external `Store`; the cache stays bounded either way.

## HTTP middleware

```go
mw, _ := libauth.NewMiddleware(m, libauth.HeaderIdentity("")) // reads X-User-ID

mux := http.NewServeMux()
mux.Handle("POST /articles", mw.Require(libauth.Perm("article", "create"))(create))
mux.Handle("POST /publish",  mw.RequireAll(libauth.Perm("article", "edit"), libauth.Perm("article", "publish"))(publish))
mux.Handle("GET /audit",     mw.RequireRole("admin")(audit))
```

- Missing identity or user → `401`; authenticated but denied → `403` with a `*PermissionDeniedError` (`errors.Is(err, libauth.ErrPermissionDenied)`).
- Inside the handler, `libauth.UserFromContext(r.Context())` returns the `*User`.
- The identity source is an explicit `IdentityFunc`; `HeaderIdentity` is for demos only. For JWT/Branca, read the `Authorization` header, `Decode`, return `sub` ([_examples/jwtauth](_examples/jwtauth/main.go)). Custom responses: `WithOnError`.

## JWT

`jwt` ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)) does HS256 or EdDSA with the standard library. The algorithm is pinned at construction, the signature is verified before parsing, `Encode` requires `sub` and `exp` (or `WithTTL`), and HS256 keys must be at least 32 bytes.

```go
auth, _ := jwt.New(secret, jwt.WithTTL(15*time.Minute), jwt.WithIssuer("login"),
    jwt.WithExpectedIssuer("login"))

token, _  := auth.Encode(jwt.Claims{Subject: "bob"})
claims, _ := auth.Decode(token)

identity := func(r *http.Request) (libauth.UserID, error) {
    token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    claims, err := auth.Decode(token)
    if err != nil { return "", err }
    return libauth.UserID(claims.Subject), nil
}
mw, _ := libauth.NewMiddleware(m, identity)

issuer, _   := jwt.NewEdDSA(priv)          // sign + verify
verifier, _ := jwt.NewVerifierEdDSA(pub)   // verify only
```

## Branca

`branca` implements the [branca spec](https://github.com/tuupola/branca-spec): XChaCha20-Poly1305, base62, needs `golang.org/x/crypto`. The timestamp lives in the authenticated header; the TTL is chosen at decode time.

| | `jwt` | `branca` |
|---|---|---|
| Payload | signed, readable | encrypted, opaque |
| Expiry | fixed at signing | decided at verification |
| Keys | Ed25519 allows asymmetric | symmetric only |
| Dependency | stdlib | `golang.org/x/crypto` |

```go
type Session struct{ Sub string `json:"sub"` }

func (s Session) MarshalBinary() ([]byte, error)  { return json.Marshal(s) }
func (s *Session) UnmarshalBinary(b []byte) error { return json.Unmarshal(b, s) }

b, _ := branca.New(key) // 32 bytes

token, _ := b.Encode(Session{Sub: "bob"})
var s Session
b.Decode(token, 15*time.Minute, &s)
```

`Encode` / `Decode` accept anything implementing `encoding.BinaryMarshaler` / `encoding.BinaryUnmarshaler`.

## Performance

A warm `Check` is a map lookup with zero allocations (`TestCheckWarmPathZeroAllocs` pins it); the cold path scales with the number of grants.

| Scale | Warm | Cold |
|---|---|---|
| single user + `*` | **56 ns/op**, 0 allocs | 1.0 µs/op, 18 allocs |
| 100 roles × 10 permissions | 77 ns/op, 0 allocs | 74 µs/op, 922 allocs |
| 100 roles × 100 permissions | 76 ns/op, 0 allocs | 0.70 ms/op, 1,522 allocs |
| 1,000 roles × 100 permissions | 80 ns/op, 0 allocs | 7.2 ms/op, 15,037 allocs |

Tokens, ~80-byte identity payload:

| Operation | HS256 | EdDSA | Branca |
|---|---|---|---|
| `Encode` | 2.0 µs | 16.7 µs | 5.1 µs |
| `Decode` | 4.4 µs | 39.0 µs | 2.9 µs |
| `Decode`, ~1 KiB payload | 1.9 ms | — | 0.07 ms |

- EdDSA verification is dominated by Ed25519 itself; use HS256 if that is your bottleneck.
- With large payloads Branca is ~27× faster than HS256: AEAD work is constant-size, JSON claims are not.

Ryzen 9 7900X, Go 1.27. Reproduce with `make bench`.

## Development

```bash
make test     # go vet + go test -race
make bench    # authz / jwt / branca benchmarks
make run      # example01 on :8080
go run ./_examples/jwtauth   # JWT bearer demo on :8081
```

More examples in `_examples/` and `example_test.go`.

MIT License.
