English | [简体中文](README-zh.md)

# libauth — Multi-Role Permission System (RBAC)

`libauth` is a Go library for multi-role access control (RBAC): a user may hold several roles, roles may inherit from one another, and permissions are `resource:action` strings with wildcard support. The core package has zero third-party dependencies and ships with a thread-safe in-memory store, a pluggable `Store` interface, `net/http` middleware, and built-in JWT and Branca token implementations.

## Features

- Multiple roles per user, single-parent inheritance, wildcard permissions (`article:*` / `*`) and direct grants.
- Built-in `read` / `write` / `exec` action constants; any custom action string works too.
- Pluggable `Store` interface; the bundled `MemoryStore` is the reference implementation.
- HTTP middleware `Require` / `RequireAll` / `RequireAny` / `RequireRole` that injects the resolved user into the `context`.
- Two token formats: `jwt` (HS256 / Ed25519, stdlib only) and `branca` (XChaCha20-Poly1305, encrypted, no plaintext).
- Zero third-party dependencies in the core, concurrency-safe, and a cache-hit `Check` is a single map lookup.

## Quick start

```go
m := libauth.New()

// The last argument is the parent role; pass "" for none.
m.CreateRole("editor",  []libauth.Permission{{"article", "create"}, {"article", "edit"}}, "")
m.CreateRole("viewer",  []libauth.Permission{{"article", "read"}}, "")
m.CreateRole("publisher", []libauth.Permission{{"article", "publish"}}, "editor") // inherits editor
m.CreateRole("admin",   []libauth.Permission{{"*", ""}}, "")                       // global wildcard

m.CreateUser("bob",   "editor", "viewer")  // multiple roles
m.CreateUser("alice", "admin")

m.Check("bob",   libauth.Permission{"article", "create"}) // nil
m.Check("bob",   libauth.Permission{"article", "delete"}) // ErrPermissionDenied
m.Check("alice", libauth.Permission{"article", "delete"}) // nil (wildcard)

m.AssignRole("bob", "publisher") // dynamic grant
m.Check("bob", libauth.Permission{"article", "publish"})  // nil
```

## Permission format

A `Permission` is a `resource:action` string; the number of segments is open-ended (e.g. `tenant:article:read`). `libauth.ActionRead`, `libauth.ActionWrite` and `libauth.ActionExec` mean read, write and execute respectively; they are string constants, not a closed enum. Custom actions need no registration:

```go
read := libauth.Permission{Resource: "article", Action: libauth.ActionRead}
publish := libauth.Permission{Resource: "article", Action: "publish"} // custom action
```

The three built-in actions are independent: `write` does not imply `read`, and `exec` implies neither. Built-in and custom actions follow the same exact-match and wildcard rules:

| Granted (pattern) | Checked (actual) | Result |
|---|---|---|
| `article:create` | `article:create` | ✅ |
| `article:*` | `article:delete` | ✅ |
| `*` | anything | ✅ |
| `article:read` | `article:delete` | ❌ |
| `article:read` | `article:read:extra` | ❌ (segment count differs) |

## API overview

`Enforcer` (see [authz/authz.go](authz/authz.go)) is the RBAC orchestration layer: it combines the Store with the domain rules and answers allowed/denied.

- Users: `CreateUser` / `DeleteUser` / `GetUser` / `ListUsers`
- Role assignment: `AssignRole` / `RevokeRole` / `RolesFor` (including the inheritance chain)
- Roles: `CreateRole` / `UpdateRole` / `DeleteRole` / `GetRole` / `ListRoles` / `SetParent`
- Permissions: `GrantPermission` / `RevokePermission` (roles); `GrantDirectPermission` / `RevokeDirectPermission` (users)
- Checks: `Check` (returns an error), `HasPermission`, `HasRole` (direct roles only, no inheritance); combine them with your own loops
- Aggregation: `PermissionsFor` (the user's full effective permission set, deduplicated and sorted)
- Construction: `libauth.New()`, plus the optional `libauth.WithStore(s)`, `libauth.WithMaxDepth(n)`, `libauth.WithCacheSize(n)`, `libauth.WithCacheTTL(d)` and `libauth.WithUnboundedCache()`; the user cache defaults to 10,000 entries and expires after 24 hours without access

Concurrency contract: reads (`Check` / `Has*` / `PermissionsFor` and friends) may run concurrently; writes (mutations such as `AssignRole`) are serialized against each other and never lose updates; once a mutation returns, subsequent reads observe it. User-level writes invalidate only that user's cache entry; role-level writes flush the whole user cache. The `Enforcer` must be the only writer to its `Store`.

The `Store` interface (see [store/store.go](store/store.go)) defines the persistence contract; the bundled `MemoryStore` is the reference implementation. To back libauth with MySQL/Postgres, implement the interface and inject it via `libauth.New(libauth.WithStore(myStore))`.

### In-memory model and sizing

`MemoryStore` and the `Enforcer` cache have different memory semantics and should not be confused:

| Data | When it enters memory | Lifetime |
|---|---|---|
| `MemoryStore` `User` / `Role` | immediately, on `CreateUser` / `CreateRole` | until the matching `Delete*`; this is an in-memory implementation, not a cache |
| `Enforcer` user cache (direct roles + `grantedSet`) | lazily, on the first `Check` / `HasRole` / `HasPermission` / `PermissionsFor` | at most 10,000 users by default, expiring after 24 hours without access; second-chance eviction when full |

Registration itself builds no reverse index or permission cache in the `Enforcer`; a cold user only occupies a cache slot briefly once accessed. User-level writes remove that one entry; role-level writes flush the whole user cache, which is why there is no `roleHolders` / `directRoles` index that grows with the number of registrations.

Reference measurements on Linux/amd64 with Go 1.27 (100,000 users, one role each with one permission, heap after a forced GC):

| Stage | Heap | Notes |
|---|---:|---|
| `MemoryStore` only, users stored | 13 MB | 131 B/user, the registration data itself |
| after `Enforcer.CreateUser` for all users | 13 MB | registration adds no Enforcer index |
| after one `Check` per user | 30 MB | the cache holds at most 10,000 users, about +16 MB here |

Actual usage varies with user ID length, role count, permission count and role combinations. Rules of thumb:

- **A few thousand to a few tens of thousands of users**: the default setup is usually fine;
- **100,000 users**: avoid `MemoryStore` and use an external Store; the `Enforcer` cache stays bounded by default;
- **Millions of registered users**: an external Store is mandatory. The user cache is still capped at 10,000 entries; entry size grows with the permission volume, so tune it with `WithCacheSize` / `WithCacheTTL`, or opt back into the old unbounded behaviour with `WithUnboundedCache()`.

## HTTP middleware

```go
mw, _ := libauth.NewMiddleware(m, libauth.HeaderIdentity("")) // reads X-User-ID by default

mux := http.NewServeMux()
mux.Handle("POST /articles", mw.Require  (libauth.Permission{"article", "create"})(create))
mux.Handle("GET  /articles", mw.Require  (libauth.Permission{"article", "read"})  (list))
mux.Handle("POST /publish",  mw.RequireAll(libauth.Permission{"article", "edit"}, libauth.Permission{"article", "publish"})(publish))
mux.Handle("GET  /audit",    mw.RequireRole("admin")(audit))
```

- Identity failure or an unknown user → `401`; authenticated but lacking permission → `403` (a `*PermissionDeniedError`, matchable with `errors.Is(err, libauth.ErrPermissionDenied)`). The denial payload names the gap: `Required` for a single permission, `RequiredAny` for `RequireAny`, `RequiredRole` for `RequireRole`.
- After the guard passes, `libauth.UserFromContext(r.Context())` returns the `*User`.
- The identity source is an `IdentityFunc(r *http.Request) (UserID, error)` and must be passed explicitly (`nil` is an error, never a silent fallback to a plaintext header); `HeaderIdentity("")` reads `X-User-ID` and is meant for demos and internal networks only. To use JWT / Branca, write a few lines yourself: read the `Authorization` header, call `Decode`, return `sub`. See [_examples/jwtauth](_examples/jwtauth/main.go) for a full example.
- Custom error responses: `libauth.NewMiddleware(m, identity, libauth.WithOnError(handler))`. `NewMiddleware` accepts any `Authorizer` implementation; `*Enforcer` works out of the box.

## JWT tokens

The `jwt` subpackage ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)) signs and verifies JWTs — HS256 and Ed25519, both from the standard library, zero third-party dependencies. Security trade-offs: the algorithm is pinned at construction (so `alg: "none"` and cross-algorithm confusion are structurally impossible), `Encode` requires `exp` (or `WithTTL`), the signature is verified before claims are parsed, `exp` / `nbf` / `iat` are all validated (`WithLeeway` tolerates clock skew), and HS256 keys must be at least 32 bytes.

A single `JWT` type covers every deployment shape, with just two verbs, `Encode` and `Decode`:

```go
auth, _ := jwt.New(secret, jwt.WithTTL(15*time.Minute), jwt.WithIssuer("login"),
    jwt.WithExpectedIssuer("login"))

token, _  := auth.Encode(jwt.Claims{Subject: "bob"})
claims, _ := auth.Decode(token) // claims.Subject / ExpiresAt / Extra

// Wire it into the middleware — the token's sub is the user ID.
identity := func(r *http.Request) (libauth.UserID, error) {
    token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    claims, err := auth.Decode(token)
    if err != nil { return "", err }
    return libauth.UserID(claims.Subject), nil
}
mw, _ := libauth.NewMiddleware(m, identity)

// Multi-service verification, issuer-only private key: the encoder holds the private
// key, verifiers only need the public half.
issuer,   _ := jwt.NewEdDSA(priv)             // Encode + Decode
verifier, _ := jwt.NewVerifierEdDSA(pub)      // Decode only; Encode fails with ErrInvalidKey
```

## Branca tokens

The `branca` subpackage implements the [branca spec](https://github.com/tuupola/branca-spec): XChaCha20-Poly1305 encryption, base62-encoded, self-validating tokens. The security trade-offs match JWT: a single pinned algorithm, a timestamp inside the authenticated header that cannot be tampered with, a TTL checked only after successful decryption (as the spec requires), and keys of exactly 32 bytes.

| | `jwt` package | `branca` package |
|---|---|---|
| Payload | signed, readable in plaintext | encrypted and opaque, only key holders can read it |
| Expiry | `exp` fixed at signing time | TTL decided **at verification**; the same token can differ per consumer |
| Trust model | Ed25519 allows asymmetric keys | symmetric key, single trust domain |
| Dependency | stdlib only | `golang.org/x/crypto` |

The payload is just bytes; `Encode` / `Decode` accept any type implementing `encoding.BinaryMarshaler` / `encoding.BinaryUnmarshaler`, no generics needed:

```go
type Session struct {
    Sub string `json:"sub"`
}

func (s Session) MarshalBinary() ([]byte, error)  { return json.Marshal(s) }
func (s *Session) UnmarshalBinary(b []byte) error { return json.Unmarshal(b, s) }

b, _ := branca.New(key /* 32 bytes */)

token, _ := b.Encode(Session{Sub: "bob"})
var s Session
b.Decode(token, 15*time.Minute, &s) // the caller decides the TTL

// Wire it into the middleware by writing your own IdentityFunc.
identity := func(r *http.Request) (libauth.UserID, error) {
    token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    var s Session
    if _, err := b.Decode(token, time.Hour, &s); err != nil { return "", err }
    return libauth.UserID(s.Sub), nil
}
mw, _ := libauth.NewMiddleware(m, identity)
```

## Performance

Permission checks are the hot path. `authz.Enforcer` keeps one cache entry per accessed user (direct roles plus a flattened `grantedSet` index of `{Resource: {Action}}`). A hit only takes a read lock, does map lookups and atomically refreshes the TTL / second-chance bit, and allocates nothing; `TestCheckWarmPathZeroAllocs` pins that contract. User-level writes invalidate one entry; role-level writes flush the whole user cache at O(capacity), but role changes are infrequent administrative operations.

`make bench` runs the `Check` microbenchmarks in the `authz` package, labelled by "roles × permissions per role", with warm and cold numbers:

| Scale | Warm hit | Cold |
|---|---|---|
| single user + `*` (reference point) | **56 ns/op**, 0 allocs | 1.0 µs/op, 18 allocs |
| 100 roles × 10 permissions (1,000 grants) | 77 ns/op, 0 allocs | 74 µs/op, 922 allocs |
| 100 roles × 100 permissions (10,000 grants) | 76 ns/op, 0 allocs | 0.70 ms/op, 1,522 allocs |
| 1,000 roles × 10 permissions (10,000 grants) | 78 ns/op, 0 allocs | 0.96 ms/op, 9,037 allocs |
| 1,000 roles × 100 permissions (100,000 grants) | 80 ns/op, 0 allocs | 7.2 ms/op, 15,037 allocs |

Key observations: warm hits are essentially independent of the authorization size, but cost more than the TTL-free version because of the atomic timestamp and reference-bit updates; warm hits allocate nothing; cold cost grows linearly (mostly store reads, inheritance resolution and `grantedSet` construction). With capacity 15 and 16 users taking turns, `BenchmarkCheckWithEviction` runs at about 0.66 µs/op and 19 allocs — eviction only happens during a miss install and never enters the warm path.

Measured on an AMD Ryzen 9 7900X, Go 1.27, `-benchtime=3s`, Linux/amd64. Reproduce with:

```bash
make bench    # runs authz / jwt / branca together
```

The `jwt` and `branca` packages have hot-path benchmarks too, with a typical identity payload (`{"sub":"user-1234","scope":"read write","org":"acme"}`, ~80 bytes):

| Operation | HS256 | EdDSA | Branca |
|---|---|---|---|
| Sign (`Encode`) | 2.0 µs | 16.7 µs | 5.1 µs |
| Verify (`Decode`) | 4.4 µs | 39.0 µs | 2.9 µs |
| Verify with a ~1 KiB payload | 1.9 ms | — | 0.07 ms |

Observations:

- **All three are affordable per request**; EdDSA verification at 39 µs is mostly the cost of Ed25519 verification itself — switch to HS256 if verification is the hot-path bottleneck.
- **With large payloads Branca is ~27× faster than HS256**: JWT is base64-encoded plaintext, so a 1 KiB claim set goes through `encoding/json` deserialization; Branca is ciphertext and AEAD decryption is constant-size. That is the practical payoff of opaque payloads — a strong reason to pick Branca if your tokens carry many business fields.

## Running the demos

```bash
make run                        # example01: X-User-ID header auth
go run ./_examples/jwtauth      # JWT bearer auth

# In example01:
# alice is an admin and may delete
curl -X DELETE -H "X-User-ID: alice" localhost:8080/articles/1
# carol only has the viewer role, so this is denied (403)
curl -X POST -H "X-User-ID: carol" localhost:8080/articles -d '{"title":"hi"}'
# dave inherits editor through publisher, so this is allowed
curl -X POST -H "X-User-ID: dave" localhost:8080/articles -d '{"title":"hi"}'
```

More examples live in the `main.go` files under `_examples/`, and in `example_test.go` at the repository root (runnable with `go test`).

## Development

```bash
make test    # go vet + go test -race
make bench   # run the authz Check microbenchmarks (see Performance)
make build   # build the example server into bin/
```

MIT License.
