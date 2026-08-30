# libauth — 多角色权限系统（RBAC）

`libauth` 是一个用 Go 实现的多角色权限控制（RBAC）库：用户可持有多个角色，角色可继承，权限基于 `资源:操作` 字符串并支持通配符。核心包零第三方依赖，附带线程安全的内存存储、可插拔的 `Store` 接口、`net/http` 中间件，并内置 JWT 与 Branca 两种令牌实现。

## 特性

- **多角色用户**：一个用户同时持有任意多个角色，权限取所有角色的并集。
- **角色继承**：每个角色可声明至多一个父角色（如 `publisher` 继承 `editor`），权限沿父链传递，写入时拒绝环形继承。
- **通配符权限**：`article:*` 匹配某资源的所有操作，`*` 匹配一切。
- **直接授权**：绕过角色，直接给用户授予/撤销权限。
- **可插拔存储**：内置 `MemoryStore`；实现 `Store` 接口即可接入数据库。
- **HTTP 中间件**：`Require` / `RequireAll` / `RequireAny` / `RequireRole`，校验通过后把用户注入 `context`。
- **JWT 令牌**：`jwt` 子包签发/校验 JWT（HS256 与 Ed25519，纯标准库），算法钉死、强制过期；`BearerIdentity` 一行接入中间件。
- **Branca 令牌**：`branca` 子包签发/校验加密令牌（XChaCha20-Poly1305，载荷不透明），TTL 由验证端决定；依赖 Go 官方扩展库 `golang.org/x/crypto`。
- **并发安全**：内存存储使用读写锁，检查结果为副本，外部无法破坏内部状态。
- **零依赖核心**：RBAC 与 JWT 仅标准库；仅 Branca 令牌额外依赖 `golang.org/x/crypto`，不使用该令牌的构建不会编译它。

## 快速开始

```go
package main

import (
    "fmt"
    "github.com/cupen/libauth"
)

func perm(s string) libauth.Permission {
    p, _ := libauth.ParsePermission(s)
    return p
}

func main() {
    m := libauth.New()

    // 角色：编辑者与查看者（最后一个参数是父角色，没有则传 ""）
    _ = m.CreateRole("editor", []libauth.Permission{perm("article:create"), perm("article:edit"), perm("article:read")}, "")
    _ = m.CreateRole("viewer", []libauth.Permission{perm("article:read")}, "")
    // 管理员：通配符；发布者继承编辑者
    _ = m.CreateRole("admin", []libauth.Permission{perm("*")}, "")
    _ = m.CreateRole("publisher", []libauth.Permission{perm("article:publish")}, "editor")

    // 用户：bob 同时持有 editor 与 viewer 两个角色
    _ = m.CreateUser("bob", "editor", "viewer")
    _ = m.CreateUser("alice", "admin")

    // 权限检查
    fmt.Println(m.Check("bob", perm("article:create")))   // nil（editor 授予）
    fmt.Println(m.Check("bob", perm("article:delete")))   // ErrPermissionDenied
    fmt.Println(m.Check("alice", perm("article:delete"))) // nil（admin 通配符）

    // 动态调整
    _ = m.AssignRole("bob", "publisher")
    _ = m.Check("bob", perm("article:publish")) // nil（publisher 本身授予）

    // 继承只沿父角色链传播：dave 持有 publisher，仅继承 editor 的权限，
    // 并不会获得 admin 的 "*"。
    _ = m.CreateUser("dave", "publisher")
    ok, _ := m.HasPermission("dave", perm("user:delete"))
    fmt.Println(ok) // false —— editor 链上没有 user:delete
}
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
m := libauth.New()
// ... 建角色与用户 ...
mw, err := libauth.NewMiddleware(m, libauth.HeaderIdentity("")) // 默认读 X-User-ID
if err != nil {
    log.Fatal(err)
}

parse := func(s string) libauth.Permission { p, _ := libauth.ParsePermission(s); return p }

mux := http.NewServeMux()
mux.Handle("POST /articles", mw.Require(parse("article:create"))(http.HandlerFunc(createArticle)))
mux.Handle("GET /articles", mw.Require(parse("article:read"))(http.HandlerFunc(listArticles)))
mux.Handle("POST /publish", mw.RequireAll(parse("article:edit"), parse("article:publish"))(http.HandlerFunc(publish)))
mux.Handle("GET /audit", mw.RequireRole("admin")(http.HandlerFunc(audit)))
```

- 身份失败（如缺少 `X-User-ID` 头）或用户不存在 → `401`
- 已认证但缺权限 → `403`（`*PermissionDeniedError`，可用 `errors.Is(err, libauth.ErrPermissionDenied)` 匹配）
- 通过校验后，`libauth.UserFromContext(r.Context())` 可取回 `*User`
- 自定义响应：设置 `mw.OnError`；自定义身份来源：传入自己的 `IdentityFunc`（内置 `libauth.BearerIdentity(verifier)` 可直接验签 JWT 或 branca 令牌，见下文）；自定义权限来源：`NewMiddleware` 接受任何满足 `Authorizer` 接口的实现（`*Enforcer` 开箱即用，见 [middleware/middleware.go](middleware/middleware.go)）

## JWT 令牌

`jwt` 子包提供 JWT（[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)）的签发与校验，依旧零第三方依赖——HS256 与 EdDSA（Ed25519）都来自 Go 标准库。安全取向：

- **算法钉死**：`Verifier` 只接受构造时选定的算法，`alg: "none"` 与跨算法混淆攻击在结构上不可能发生；
- **强制过期**：`Sign` 要求 claims 带 `exp`（显式设置或经 `WithTTL` 提供），忘配 TTL 会直接报错，而不是造出永不过期的令牌；
- **先验签、后解析**：签名校验先于 claims 解析；`exp` / `nbf` / `iat` 全部校验（`WithLeeway` 容忍时钟偏差），可钉死 `iss` / `aud`；
- **密钥下限**：HS256 密钥至少 32 字节。

```go
signer, err := jwt.NewSignerHS256(secret, jwt.WithTTL(15*time.Minute), jwt.WithIssuer("login"))
token, err := signer.Sign(jwt.Claims{Subject: "bob"})

verifier, err := jwt.NewVerifierHS256(secret, jwt.WithExpectedIssuer("login"))
claims, err := verifier.Verify(token) // claims.Subject / claims.ExpiresAt / claims.Extra
```

一行接入 HTTP 中间件——token 的 `sub` 即用户 ID，角色与权限仍在服务端实时解析，撤销角色立即生效，无需重发令牌：

```go
mw, err := libauth.NewMiddleware(enforcer, libauth.BearerIdentity(verifier))
```

需要"多个服务验签、仅签发方持钥"时选 EdDSA：签发方用 `jwt.NewSignerEdDSA(私钥)`，验证方只持公钥 `jwt.NewVerifierEdDSA(公钥)`。

## Branca 令牌

`branca` 子包实现 [branca 规范](https://github.com/tuupola/branca-spec)：XChaCha20-Poly1305（AEAD）加密、Base62 编码的自校验令牌。与 JWT 的取舍：

| | `jwt` 包 | `branca` 包 |
|---|---|---|
| 载荷 | 签名后明文可读（Base64） | 加密不透明，仅持钥方可读 |
| 过期 | `exp` 在签发时写死 | TTL 在**验证时**决定，同一令牌对不同消费方可有不同有效期 |
| 信任模型 | Ed25519 支持非对称（验签方无法签发） | 对称密钥，适合单一信任域 |
| 依赖 | 纯标准库 | `golang.org/x/crypto`（Go 官方扩展库） |

安全取向与 jwt 一致：算法唯一（无协商空间）、时间戳在认证头内不可篡改、TTL 校验在解密成功之后进行（规范要求）、密钥必须恰好 32 字节。载荷就是一段任意格式的字节；`Encode` / `Decode` 方法适配任何实现标准库 `encoding.BinaryMarshaler` / `encoding.BinaryUnmarshaler` 的类型——类型由传入的值携带，全程无需泛型参数：

```go
type Session struct {
    Sub   string `json:"sub"`
    Admin bool   `json:"admin,omitempty"`
}

func (s Session) MarshalBinary() ([]byte, error)  { return json.Marshal(s) }
func (s *Session) UnmarshalBinary(b []byte) error { return json.Unmarshal(b, s) }

b, err := branca.New(key /* 32 字节 */, branca.WithTTL(15*time.Minute))

token, err := b.Encode(Session{Sub: "bob"})

var session Session
err = b.Decode(token, 15*time.Minute, &session)

// 原始字节载荷直接用 Seal / Open
token, err = b.Seal([]byte("Hello world!"))
opened, err := b.Open(token, 30*time.Minute) // opened.Payload / opened.Timestamp
```

`b.VerifyBearer(token)` 与中间件直接对接（要求 `branca.WithTTL`，持有者令牌不允许永不过期）；它约定载荷是含字符串 `"sub"` 成员的 JSON，例如上面的 `Session`：

```go
mw, err := libauth.NewMiddleware(enforcer, libauth.BearerIdentity(b))
```

编解码已用规范配套的官方跨实现测试向量验证（含 ts=0 与 uint32 上限时间戳、空载荷、逐字节段篡改样例，编码方向按向量来源参数确定性复现）。

## 目录结构

```
libauth/
├── libauth.go              # 包入口：所有公共类型的别名再导出（API 兼容层）
├── errors.go               # 哨兵错误再导出（按来源聚合）
├── middleware.go           # 中间件再导出（兼容层，签名不变）
├── bearer.go                 # BearerIdentity：JWT / branca 验签 → IdentityFunc 粘合层
├── authz/                  # Enforcer 子包（RBAC 编排层）
│   ├── authz.go            #   Enforcer 结构、New、WithStore、WithMaxDepth
│   ├── users.go            #   用户 CRUD、角色分配、直接授权
│   ├── roles.go            #   角色 CRUD、权限管理、父角色
│   ├── resolve.go          #   继承链与有效权限解析
│   ├── check.go            #   角色/权限检查
│   ├── validate.go         #   继承环与深度校验
│   ├── errors.go           #   ErrCyclicInheritance / ErrInheritanceDepth
│   └── enforcer_test.go
├── model/                  # 核心数据类型子包（纯数据，无持久化/HTTP 依赖）
│   ├── user.go             #   User / UserID
│   ├── role.go             #   Role / RoleName 与继承辅助方法
│   ├── permission.go       #   Permission 与通配符匹配
│   ├── errors.go           #   PermissionDeniedError / ErrPermissionDenied / ErrInvalidPermission
│   └── model_test.go
├── store/                  # 存储层子包
│   ├── store.go            # Store 持久化接口
│   ├── errors.go           # 存储级哨兵错误
│   ├── memory.go           # 线程安全内存存储（参考实现）
│   ├── memory_users.go     #   用户部分
│   ├── memory_roles.go     #   角色部分
│   └── memory_test.go
├── middleware/             # HTTP 守卫子包（依赖 Authorizer 接口，不依赖 Enforcer）
│   ├── middleware.go       #   Authorizer、Middleware、NewMiddleware 与内部辅助
│   ├── require.go          #   Require / RequireAll / RequireAny / RequireRole
│   ├── identity.go         #   IdentityFunc / HeaderIdentity
│   ├── context.go          #   WithUser / UserFromContext
│   └── middleware_test.go
├── jwt/                    # JWT 子包（纯标准库，算法钉死）
│   ├── jwt.go              #   Signer / Verifier、选项与校验流程
│   ├── claims.go           #   Claims / Audience 与 JSON 编解码
│   ├── alg.go              #   HS256 与 EdDSA（Ed25519）实现
│   ├── errors.go           #   哨兵错误
│   └── jwt_test.go
├── branca/                   # Branca 子包（XChaCha20-Poly1305 加密令牌）
│   ├── branca.go             #   Codec / Claims、Seal / Open / VerifyBearer
│   ├── base62.go             #   规范的 base62 编解码
│   ├── errors.go             #   哨兵错误
│   └── branca_test.go
├── middleware_test.go      # 中间件集成测试（根包层）
├── example_test.go         # godoc 示例（go test 验证输出）
└── _examples/              # 独立演示程序（下划线前缀，go ./... 不扫描）
    ├── basic/              # 无 HTTP 的核心流程演示
    ├── customstore/        # 自定义 JSON 文件存储演示
    ├── example01/          # 可运行的 HTTP 演示服务（X-User-ID 头认证）
    └── jwtauth/            # JWT 持有者认证演示（/login 签发 + Bearer 验签）
```

## 运行演示

```bash
make run            # 或 go run ./_examples/example01

# alice 是 admin，可以删除
curl -X DELETE -H "X-User-ID: alice" localhost:8080/articles/1
# carol 只有 viewer 角色，被拒绝（403）
curl -X POST -H "X-User-ID: carol" localhost:8080/articles -d '{"title":"hi"}'
# dave 经 publisher 继承 editor，可以创建
curl -X POST -H "X-User-ID: dave" localhost:8080/articles -d '{"title":"hi"}'
# 查看某用户的有效角色与权限
curl -H "X-User-ID: bob" localhost:8080/whoami
```

JWT 演示（独立服务，Bearer 认证）：

```bash
go run ./_examples/jwtauth
TOKEN=$(curl -s -X POST -d '{"username":"bob"}' localhost:8081/login | sed -E 's/.*"token":"([^"]+)".*/\1/')
curl -H "Authorization: Bearer $TOKEN" localhost:8081/whoami
curl -X POST -H "Authorization: Bearer $TOKEN" -d '{"title":"hi"}' localhost:8081/articles
# carol 登录后创建文章 → 403（viewer 只读）
```

## 更多示例

| 位置 | 内容 |
|---|---|
| [example_test.go](example_test.go) | 可运行的 godoc 示例，`go test` 会实际执行并验证输出：多角色并集、角色继承、通配符、动态授权、直接授权、`Check` 错误处理、中间件 |
| [_examples/basic](_examples/basic/main.go) | 无 HTTP 的核心流程演示：定义角色 → 多角色用户 → 权限检查 → 运行时授权调整，`go run ./_examples/basic` |
| [_examples/customstore](_examples/customstore/main.go) | 通过实现 `Store` 接口接入 JSON 文件持久化，演示"建库 → 重启 → 从磁盘恢复"的完整流程，`go run ./_examples/customstore` |
| [_examples/example01](_examples/example01/main.go) | HTTP 演示服务（`make run`），含 `/whoami`、文章 CRUD 等受保护端点 |
| [_examples/jwtauth](_examples/jwtauth/main.go) | JWT 持有者认证演示：`/login` 签发短时令牌，中间件经 `BearerIdentity` 验签并实时解析权限 |

## 开发

```bash
make test    # go vet + go test
make build   # 编译示例服务到 bin/
```

MIT License.
