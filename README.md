# libauth — 多角色权限系统（RBAC）

`libauth` 是一个用 Go 实现的多角色权限控制（RBAC）库：用户可持有多个角色，角色可继承，权限基于 `资源:操作` 字符串并支持通配符。核心包零第三方依赖，附带线程安全的内存存储、可插拔的 `Store` 接口和 `net/http` 中间件。

## 特性

- **多角色用户**：一个用户同时持有任意多个角色，权限取所有角色的并集。
- **角色继承**：角色可声明父角色（如 `publisher` 继承 `editor`），权限沿继承链传递，写入时拒绝环形继承。
- **通配符权限**：`article:*` 匹配某资源的所有操作，`*` 匹配一切。
- **直接授权**：绕过角色，直接给用户授予/撤销权限。
- **可插拔存储**：内置 `MemoryStore`；实现 `Store` 接口即可接入数据库。
- **HTTP 中间件**：`Require` / `RequireAll` / `RequireAny` / `RequireRole`，校验通过后把用户注入 `context`。
- **并发安全**：内存存储使用读写锁，检查结果为副本，外部无法破坏内部状态。
- **零依赖**：仅标准库。

## 快速开始

```go
package main

import (
    "fmt"
    "github.com/cupen/libauth"
)

func main() {
    m := libauth.New()

    // 角色：编辑者与查看者
    _ = m.CreateRole("editor", []libauth.Permission{"article:create", "article:edit", "article:read"})
    _ = m.CreateRole("viewer", []libauth.Permission{"article:read"})
    // 管理员：通配符；发布者继承编辑者
    _ = m.CreateRole("admin", []libauth.Permission{"*"})
    _ = m.CreateRole("publisher", []libauth.Permission{"article:publish"}, "editor")

    // 用户：bob 同时持有 editor 与 viewer 两个角色
    _ = m.CreateUser("bob", "editor", "viewer")
    _ = m.CreateUser("alice", "admin")

    // 权限检查
    fmt.Println(m.Check("bob", "article:create"))  // nil（editor 授予）
    fmt.Println(m.Check("bob", "article:delete"))  // ErrPermissionDenied
    fmt.Println(m.Check("alice", "article:delete")) // nil（admin 通配符）

    // 动态调整
    _ = m.AssignRole("bob", "publisher")
    _ = m.Check("bob", "article:publish") // nil（publisher 本身授予）

    // 继承只沿父角色链传播：dave 持有 publisher，仅继承 editor 的权限，
    // 并不会获得 admin 的 "*"。
    _ = m.CreateUser("dave", "publisher")
    ok, _ := m.HasPermission("dave", "user:delete")
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
- 角色：`CreateRole` / `UpdateRole` / `DeleteRole` / `GetRole` / `ListRoles` / `AddParent`
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

mux := http.NewServeMux()
mux.Handle("POST /articles", mw.Require("article:create")(http.HandlerFunc(createArticle)))
mux.Handle("GET /articles", mw.Require("article:read")(http.HandlerFunc(listArticles)))
mux.Handle("POST /publish", mw.RequireAll("article:edit", "article:publish")(http.HandlerFunc(publish)))
mux.Handle("GET /audit", mw.RequireRole("admin")(http.HandlerFunc(audit)))
```

- 身份失败（无 `X-User-ID`）或用户不存在 → `401`
- 已认证但缺权限 → `403`（`*PermissionDeniedError`，可用 `errors.Is(err, libauth.ErrPermissionDenied)` 匹配）
- 通过校验后，`libauth.UserFromContext(r.Context())` 可取回 `*User`
- 自定义响应：设置 `mw.OnError`；自定义身份来源（如 JWT）：传入自己的 `IdentityFunc`；自定义权限来源：`NewMiddleware` 接受任何满足 `Authorizer` 接口的实现（`*Enforcer` 开箱即用，见 [middleware/middleware.go](middleware/middleware.go)）

## 目录结构

```
libauth/
├── libauth.go              # 包入口：所有公共类型的别名再导出（API 兼容层）
├── errors.go               # 哨兵错误再导出（按来源聚合）
├── middleware.go           # 中间件再导出（兼容层，签名不变）
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
├── middleware_test.go      # 中间件集成测试（根包层）
├── example_test.go         # godoc 示例（go test 验证输出）
└── _examples/              # 独立演示程序（下划线前缀，go ./... 不扫描）
    ├── basic/              # 无 HTTP 的核心流程演示
    ├── customstore/        # 自定义 JSON 文件存储演示
    └── example01/          # 可运行的 HTTP 演示服务
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

## 更多示例

| 位置 | 内容 |
|---|---|
| [example_test.go](example_test.go) | 可运行的 godoc 示例，`go test` 会实际执行并验证输出：多角色并集、角色继承、通配符、动态授权、直接授权、`Check` 错误处理、中间件 |
| [_examples/basic](_examples/basic/main.go) | 无 HTTP 的核心流程演示：定义角色 → 多角色用户 → 权限检查 → 运行时授权调整，`go run ./_examples/basic` |
| [_examples/customstore](_examples/customstore/main.go) | 通过实现 `Store` 接口接入 JSON 文件持久化，演示"建库 → 重启 → 从磁盘恢复"的完整流程，`go run ./_examples/customstore` |
| [_examples/example01](_examples/example01/main.go) | HTTP 演示服务（`make run`），含 `/whoami`、文章 CRUD 等受保护端点 |

## 开发

```bash
make test    # go vet + go test
make build   # 编译示例服务到 bin/
```

MIT License.
