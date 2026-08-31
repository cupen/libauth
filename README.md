# libauth — 多角色权限系统（RBAC）

`libauth` 是一个用 Go 实现的多角色权限控制（RBAC）库：用户可持有多个角色，角色可继承，权限基于 `资源:操作` 字符串并支持通配符。核心包零第三方依赖，附带线程安全的内存存储、可插拔的 `Store` 接口、`net/http` 中间件，并内置 JWT 与 Branca 两种令牌实现。

## 特性

- 多角色 + 单链继承 + 通配符权限（`article:*` / `*`）+ 直接授权。
- 可插拔 `Store` 接口；内置 `MemoryStore` 是参考实现。
- HTTP 中间件 `Require` / `RequireAll` / `RequireAny` / `RequireRole`，通过后把用户注入 `context`。
- 两种令牌:`jwt`（HS256 / Ed25519,纯标准库）、`branca`（XChaCha20-Poly1305,强加密，无铭文）
- 核心零三方依赖,并发安全,`Check` 在缓存命中路径上是一次 map 查找。

## 快速开始

```go
m := libauth.New()

// 角色：最后一个参数是父角色，没有则传 ""
m.CreateRole("editor",  []libauth.Permission{{"article", "create"}, {"article", "edit"}}, "")
m.CreateRole("viewer",  []libauth.Permission{{"article", "read"}}, "")
m.CreateRole("publisher", []libauth.Permission{{"article", "publish"}}, "editor") // 继承 editor
m.CreateRole("admin",   []libauth.Permission{{"*", ""}}, "")                       // 全局通配

m.CreateUser("bob",   "editor", "viewer")  // 多角色
m.CreateUser("alice", "admin")

m.Check("bob",   libauth.Permission{"article", "create"}) // nil
m.Check("bob",   libauth.Permission{"article", "delete"}) // ErrPermissionDenied
m.Check("alice", libauth.Permission{"article", "delete"}) // nil（通配符）

m.AssignRole("bob", "publisher") // 动态授权
m.Check("bob", libauth.Permission{"article", "publish"})  // nil
```

## 权限格式

`Permission` 是 `资源:操作` 字符串，段数可扩展（如 `tenant:article:read`）：

| 已授予（模式） | 检查（实际） | 结果 |
|---|---|---|
| `article:create` | `article:create` | ✅ |
| `article:*` | `article:delete` | ✅ |
| `*` | 任意 | ✅ |
| `article:read` | `article:delete` | ❌ |
| `article:read` | `article:read:extra` | ❌（段数不同） |

## API 概览

`Enforcer`（见 [authz/authz.go](authz/authz.go)）—— RBAC 编排层，把 Store 与领域规则揉到一起给出"允许/拒绝"的答案：

- 用户：`CreateUser` / `DeleteUser` / `GetUser` / `ListUsers`
- 角色分配：`AssignRole` / `RevokeRole` / `RolesFor`（含继承链）
- 角色：`CreateRole` / `UpdateRole` / `DeleteRole` / `GetRole` / `ListRoles` / `SetParent`
- 权限：`GrantPermission` / `RevokePermission`（角色）；`GrantDirectPermission` / `RevokeDirectPermission`（用户直授）
- 检查：`Check`（返回错误）、`HasPermission`、`HasAllPermissions`、`HasAnyPermission`、`HasRole` / `HasAnyRole` / `HasAllRoles`
- 汇总：`PermissionsFor`（用户的有效权限全集，去重排序）
- 构造：`libauth.New()`，可选 `libauth.WithStore(s)`、`libauth.WithMaxDepth(n)`

`Store` 接口（见 [store/store.go](store/store.go)）定义了持久化契约，内置 `MemoryStore` 是参考实现；接入 MySQL/Postgres 时实现该接口并通过 `libauth.New(libauth.WithStore(myStore))` 注入。

## HTTP 中间件

```go
mw, _ := libauth.NewMiddleware(m, libauth.HeaderIdentity("")) // 默认读 X-User-ID

mux := http.NewServeMux()
mux.Handle("POST /articles", mw.Require  (libauth.Permission{"article", "create"})(create))
mux.Handle("GET  /articles", mw.Require  (libauth.Permission{"article", "read"})  (list))
mux.Handle("POST /publish",  mw.RequireAll(libauth.Permission{"article", "edit"}, libauth.Permission{"article", "publish"})(publish))
mux.Handle("GET  /audit",    mw.RequireRole("admin")(audit))
```

- 身份失败或用户不存在 → `401`；已认证但缺权限 → `403`（`*PermissionDeniedError`，可用 `errors.Is(err, libauth.ErrPermissionDenied)` 匹配）。
- 通过校验后 `libauth.UserFromContext(r.Context())` 拿到 `*User`。
- 自定义响应写 `mw.OnError`；身份来源是个 `IdentityFunc(r *http.Request) (UserID, error)`,默认是 `HeaderIdentity("")` 读 `X-User-ID`。要接 JWT / Branca,自己写几行:取 `Authorization` 头、调 `Verify` 或 `Decode`、返回 `sub`。完整样板见 [_examples/jwtauth](_examples/jwtauth/main.go)。`NewMiddleware` 也接受任何 `Authorizer` 实现,`*Enforcer` 开箱即用。

## JWT 令牌

`jwt` 子包（[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)）签发/校验 JWT——HS256 与 Ed25519 都来自标准库,零三方依赖。安全取舍:算法钉死在构造时（`alg: "none"` 与跨算法混淆在结构上不可能）、`Sign` 强制要求 `exp`（或 `WithTTL`）否则报错、签名先于 claims 解析、`exp`/`nbf`/`iat` 全部校验（`WithLeeway` 容忍时钟漂移）、HS256 密钥至少 32 字节。

```go
signer, _ := jwt.NewSignerHS256   (secret, jwt.WithTTL(15*time.Minute), jwt.WithIssuer("login"))
verifier, _ := jwt.NewVerifierHS256(secret, jwt.WithExpectedIssuer("login"))

token, _ := signer.Sign(jwt.Claims{Subject: "bob"})
claims, _ := verifier.Verify(token) // claims.Subject / ExpiresAt / Extra

// 接入中间件 —— token 的 sub 即用户 ID,几行 IdentityFunc 就行
identity := func(r *http.Request) (libauth.UserID, error) {
    token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    claims, err := verifier.Verify(token)
    if err != nil { return "", err }
    return libauth.UserID(claims.Subject), nil
}
mw, _ := libauth.NewMiddleware(m, identity)

// 多服务验签、签发方独占密钥的场景选 EdDSA
signer,   _ := jwt.NewSignerEdDSA  (priv)
verifier, _ := jwt.NewVerifierEdDSA(pub)
```

## Branca 令牌

`branca` 子包实现 [branca 规范](https://github.com/tuupola/branca-spec):XChaCha20-Poly1305 加密、Base62 编码的自校验令牌。安全取舍与 JWT 一致:算法唯一、时间戳在认证头内不可篡改、TTL 在解密成功之后校验(规范要求)、密钥恰好 32 字节。

| | `jwt` 包 | `branca` 包 |
|---|---|---|
| 载荷 | 签名后明文可读 | 加密不透明,仅持钥方可读 |
| 过期 | `exp` 在签发时写死 | TTL 在**验证时**决定,同一令牌对不同消费方可不同 |
| 信任模型 | Ed25519 可非对称 | 对称密钥,单一信任域 |
| 依赖 | 纯标准库 | `golang.org/x/crypto` |

载荷即字节流;`Encode` / `Decode` 接受任何实现 `encoding.BinaryMarshaler` / `encoding.BinaryUnmarshaler` 的类型,无需泛型:

```go
type Session struct {
    Sub string `json:"sub"`
}

func (s Session) MarshalBinary() ([]byte, error)  { return json.Marshal(s) }
func (s *Session) UnmarshalBinary(b []byte) error { return json.Unmarshal(b, s) }

b, _ := branca.New(key /* 32 字节 */)

token, _ := b.Encode(Session{Sub: "bob"})
var s Session
b.Decode(token, 15*time.Minute, &s) // TTL 在调用方决定

// 接入中间件 —— 自己拼 IdentityFunc
identity := func(r *http.Request) (libauth.UserID, error) {
    token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
    var s Session
    if _, err := b.Decode(token, time.Hour, &s); err != nil { return "", err }
    return libauth.UserID(s.Sub), nil
}
mw, _ := libauth.NewMiddleware(m, identity)
```

## 性能

权限检查是热路径,`authz.Enforcer` 对每个用户维护已授予权限集合的内存缓存(`grantedSet`,扁平化 `{Resource: {Action}}` 索引),命中只走几次 map 查找;写路径由 `Enforcer` 集中失效,读侧无锁。

`make bench` 跑 `authz` 包的 `Check` 微基准,规模按"角色数 × 每角色权限数"标注,缓存命中与冷启动两路数字:

| 规模 | 命中 | 冷启 |
|---|---|---|
| 单用户 + `*`(参照点) | **22 ns/op**,0 allocs | 1.0 µs/op,15 allocs |
| 100 角色 × 10 权限(1 000 grants) | 51 ns/op,0 allocs | 132 µs/op,917 allocs |
| 100 角色 × 100 权限(10 000 grants) | 54 ns/op,0 allocs | 1.08 ms/op,1517 allocs |
| 1000 角色 × 10 权限(10 000 grants) | 62 ns/op,0 allocs | 1.83 ms/op,9030 allocs |
| 1000 角色 × 100 权限(100 000 grants) | 61 ns/op,0 allocs | 11.4 ms/op,15 030 allocs |

关键观察:命中与规模几乎无关(50–62 ns,因为是一次 map 查找)、命中路径 0 allocs、冷启随规模线性(主要开销在 store 读 + 继承链解析 + `grantedSet` 构造)。

数字采集:AMD Ryzen 7 3700X,Go 1.25,`-benchtime=3s`,Linux/amd64。复现:

```bash
make bench    # authz / jwt / branca 三个包一起跑
```

`jwt` 和 `branca` 包也有热路径基准,载荷是典型身份 claim(`{"sub":"user-1234","scope":"read write","org":"acme"}`,约 80 字节):

| 操作 | HS256 | EdDSA | Branca |
|---|---|---|---|
| 签发(`Sign` / `Encode`) | 9.4 µs | 25.8 µs | 7.8 µs |
| 校验(`Verify` / `Decode`) | 10.2 µs | 63.2 µs | 5.4 µs |
| ~1 KiB 载荷的校验 | 5.8 ms | — | 0.11 ms |

观察:

- **HS256 与 Branca 校验同量级**(~5–10 µs),均适合每次请求都验签。EdDSA 校验 63 µs,主要来自 Ed25519 验签本身的成本;若校验是热路径瓶颈,改用 HS256。
- **Branca 签发比 HS256 快约 17%**(密文不需要 base64 编码、JWT 头部不需要 JSON 序列化),EdDSA 签发 26 µs 比 HS256 慢约 2.7×,但仍是每次请求可承受的成本。
- **大载荷下 Branca 比 HS256 快 ~50 倍**:JWT 是 base64 明文,1 KiB claim 反序列化在 `encoding/json` 里要走一遍;Branca 是密文,AEAD 解密是定长操作。这是「载荷不透明」换来的实际收益——如果你的 token 要带不少业务字段,这是选 Branca 的硬理由。

## 运行演示

```bash
make run                        # example01：X-User-ID 头认证
go run ./_examples/jwtauth      # JWT 持有者认证

# example01 里:
# alice 是 admin，可以删除
curl -X DELETE -H "X-User-ID: alice" localhost:8080/articles/1
# carol 只有 viewer 角色，被拒绝（403）
curl -X POST -H "X-User-ID: carol" localhost:8080/articles -d '{"title":"hi"}'
# dave 经 publisher 继承 editor，可以创建
curl -X POST -H "X-User-ID: dave" localhost:8080/articles -d '{"title":"hi"}'
```

更多示例看 `_examples/` 下各目录的 `main.go`,或根目录的 `example_test.go`(可直接 `go test` 跑)。

## 开发

```bash
make test    # go vet + go test -race
make bench   # 跑 authz 包的 Check 微基准（详见「性能」一节）
make build   # 编译示例服务到 bin/
```

MIT License.
