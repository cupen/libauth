[English](README.md) | 简体中文

# libauth

Go 的多角色权限控制（RBAC）：用户持有多个角色，角色单链继承，权限是带通配符的 `资源:操作` 字符串。核心零三方依赖，可插拔 `Store`，自带 `net/http` 中间件与 JWT / Branca 令牌。

## 特性

- 多角色、单链继承、通配符权限（`article:*` / `*`）与用户直授。
- 可插拔 `Store`；内置 `MemoryStore` 为参考实现。
- `net/http` 中间件：`Require` / `RequireAll` / `RequireAny` / `RequireRole`。
- 令牌：`jwt`（HS256 / Ed25519，标准库）、`branca`（XChaCha20-Poly1305）。
- 核心零三方依赖，并发安全；命中路径一次 map 查找、零分配。

## 快速开始

```go
m := libauth.New()

// 最后一个参数是父角色，没有则传 ""
m.CreateRole("editor",    []libauth.Permission{{"article", "create"}, {"article", "edit"}}, "")
m.CreateRole("viewer",    []libauth.Permission{{"article", "read"}}, "")
m.CreateRole("publisher", []libauth.Permission{{"article", "publish"}}, "editor") // 继承 editor
m.CreateRole("admin",     []libauth.Permission{{"*", ""}}, "")                    // 通配

m.CreateUser("bob", "editor", "viewer")
m.CreateUser("alice", "admin")

m.Check("bob",   libauth.Permission{"article", "create"}) // nil
m.Check("bob",   libauth.Permission{"article", "delete"}) // ErrPermissionDenied
m.Check("alice", libauth.Permission{"article", "delete"}) // nil

m.AssignRole("bob", "publisher")
m.Check("bob", libauth.Permission{"article", "publish"})  // nil
```

## 权限

`资源:操作`，段数可扩展（`tenant:article:read`）。操作是普通字符串（`read`、`write`、`exec` 或任意名称），彼此独立：`write` 不隐含 `read`。

| 已授予 | 检查 | 结果 |
|---|---|---|
| `article:create` | `article:create` | ✅ |
| `article:*` | `article:delete` | ✅ |
| `*` | 任意 | ✅ |
| `article:read` | `article:delete` | ❌ |
| `article:read` | `article:read:extra` | ❌（段数不同） |

## API

`Enforcer`（见 [authz/authz.go](authz/authz.go)）是建立在 `Store` 之上的 RBAC 层。

- 用户：`CreateUser` / `DeleteUser` / `GetUser` / `ListUsers`
- 角色：`CreateRole` / `UpdateRole` / `DeleteRole` / `GetRole` / `ListRoles` / `SetParent` / `RolesFor`
- 授权：`AssignRole` / `RevokeRole`；`GrantPermission` / `RevokePermission`；`GrantDirectPermission` / `RevokeDirectPermission`
- 检查：`Check`（返回错误）、`HasPermission`、`HasRole`（仅直接持有）、`PermissionsFor`（有效权限全集）
- 传给 `libauth.New` 的选项：`WithStore`、`WithMaxDepth`、`WithCacheSize`、`WithCacheTTL`、`WithUnboundedCache`；缓存默认 10000 个用户、24 小时未访问过期

读可并发；写串行化，返回后立即可见。`Enforcer` 必须是其 `Store` 的唯一写入方。

`Store`（[store/store.go](store/store.go)）是持久化契约，`MemoryStore` 是参考实现。接 MySQL/Postgres 只需实现该接口并传 `libauth.WithStore(myStore)`。

### 内存

`MemoryStore` 存数据；`Enforcer` 缓存在首次检查时懒构建，注册不会产生额外索引。10 万用户的 store 约 13 MB；全部检查一次、缓存 1 万条再加约 16 MB。超过 10 万用户请换外部 `Store`，缓存始终有界。

## HTTP 中间件

```go
mw, _ := libauth.NewMiddleware(m, libauth.HeaderIdentity("")) // 读 X-User-ID

mux := http.NewServeMux()
mux.Handle("POST /articles", mw.Require(libauth.Permission{"article", "create"})(create))
mux.Handle("POST /publish",  mw.RequireAll(libauth.Permission{"article", "edit"}, libauth.Permission{"article", "publish"})(publish))
mux.Handle("GET /audit",     mw.RequireRole("admin")(audit))
```

- 身份缺失或用户不存在 → `401`；已认证但无权限 → `403`，错误为 `*PermissionDeniedError`（`errors.Is(err, libauth.ErrPermissionDenied)`）。
- 处理器内用 `libauth.UserFromContext(r.Context())` 取 `*User`。
- 身份来源必须显式传入 `IdentityFunc`；`HeaderIdentity` 仅供演示。接 JWT/Branca 就是读 `Authorization`、`Decode`、返回 `sub`（[_examples/jwtauth](_examples/jwtauth/main.go)）。自定义错误响应用 `WithOnError`。

## JWT

`jwt`（[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)）用标准库实现 HS256 与 EdDSA。算法在构造时固定，先验签后解析，`Encode` 强制要求 `sub` 和 `exp`（或用 `WithTTL`），HS256 密钥至少 32 字节。

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

issuer, _   := jwt.NewEdDSA(priv)          // 签发 + 验签
verifier, _ := jwt.NewVerifierEdDSA(pub)   // 仅验签
```

## Branca

`branca` 实现 [branca 规范](https://github.com/tuupola/branca-spec)：XChaCha20-Poly1305、Base62，依赖 `golang.org/x/crypto`。时间戳在认证头内，TTL 由解码方决定。

| | `jwt` | `branca` |
|---|---|---|
| 载荷 | 签名，明文可读 | 加密，不透明 |
| 过期 | 签发时固定 | 验证时决定 |
| 密钥 | Ed25519 可非对称 | 仅对称 |
| 依赖 | 标准库 | `golang.org/x/crypto` |

```go
type Session struct{ Sub string `json:"sub"` }

func (s Session) MarshalBinary() ([]byte, error)  { return json.Marshal(s) }
func (s *Session) UnmarshalBinary(b []byte) error { return json.Unmarshal(b, s) }

b, _ := branca.New(key) // 32 字节

token, _ := b.Encode(Session{Sub: "bob"})
var s Session
b.Decode(token, 15*time.Minute, &s)
```

`Encode` / `Decode` 接受任何实现 `encoding.BinaryMarshaler` / `encoding.BinaryUnmarshaler` 的类型。

## 性能

缓存命中的 `Check` 是一次 map 查找、零分配（`TestCheckWarmPathZeroAllocs` 固定该契约）；冷启动开销随授权数量增长。

| 规模 | 命中 | 冷启 |
|---|---|---|
| 单用户 + `*` | **56 ns/op**，0 allocs | 1.0 µs/op，18 allocs |
| 100 角色 × 10 权限 | 77 ns/op，0 allocs | 74 µs/op，922 allocs |
| 100 角色 × 100 权限 | 76 ns/op，0 allocs | 0.70 ms/op，1 522 allocs |
| 1000 角色 × 100 权限 | 80 ns/op，0 allocs | 7.2 ms/op，15 037 allocs |

令牌，约 80 字节的身份载荷：

| 操作 | HS256 | EdDSA | Branca |
|---|---|---|---|
| `Encode` | 2.0 µs | 16.7 µs | 5.1 µs |
| `Decode` | 4.4 µs | 39.0 µs | 2.9 µs |
| `Decode`，约 1 KiB 载荷 | 1.9 ms | — | 0.07 ms |

- EdDSA 验证主要耗在 Ed25519 本身；若验证是瓶颈，改用 HS256。
- 大载荷时 Branca 比 HS256 快约 27 倍：AEAD 是定长运算，JSON claims 不是。

Ryzen 9 7900X，Go 1.27。用 `make bench` 复现。

## 开发

```bash
make test     # go vet + go test -race
make bench    # authz / jwt / branca 基准
make run      # example01，:8080
go run ./_examples/jwtauth   # JWT 演示，:8081
```

更多示例见 `_examples/` 与 `example_test.go`。

MIT License.
