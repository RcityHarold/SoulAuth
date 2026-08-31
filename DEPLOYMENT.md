# SoulAuth 部署指南

本文档说明如何把 SoulAuth 部署到生产环境。

> **命名空间与数据库必须自始至终一致。** 全文统一用 `auth` / `main`
> （即 `DATABASE_NAMESPACE` / `DATABASE_NAME` 的默认值）。若你改用别的名字，
> **导入 SQL 时用的和应用启动时读到的必须是同一对** —— 这是最常见的部署失败原因：
> schema 建在一处、应用连另一处，进程照常启动、`/health` 照常返回 ok，
> 直到第一个真实请求才 500。应用现在会在启动时自检并拒绝启动，
> 但前提仍然是你把这两处对齐。

## 数据库部署

### 1. 创建数据库表结构

在启动应用程序之前，必须先运行以下SQL文件来创建数据库表结构：

```bash
# 导入表结构（注意参数是 --endpoint，不是 --conn）
surreal import --endpoint http://localhost:8000 --user root --pass root \
    --namespace auth --database main schema.sql
```

> `--namespace` / `--database` 的取值必须与应用的 `DATABASE_NAMESPACE` /
> `DATABASE_NAME` 完全一致（默认 `auth` / `main`）。

**重要说明**：
- `schema.sql` 包含所有必需的数据库表定义
- 必须在应用程序启动前执行此文件
- 这样设计符合生产环境最佳实践，避免应用程序具有DDL权限

### 2. 初始化系统数据

创建完表结构后，运行初始数据文件来创建系统角色和权限：

```bash
# 导入初始数据（ns/db 必须与上一步、以及应用配置三者一致）
surreal import --endpoint http://localhost:8000 --user root --pass root \
    --namespace auth --database main initial_data.sql
```

**`initial_data.sql` 包含的内容**：
- 系统权限（18 个，全部带 `soulauth:` 命名空间前缀）
- 系统角色（5 个预定义角色）
- 系统用户账户（用于权限分配的内部账户）
- 角色权限关联（为系统角色分配适当的权限）

## OIDC 签名密钥

ID Token 使用 RS256 签名，公钥通过 `/api/oidc/jwks` 发布。生产环境必须提供一把持久私钥：

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /etc/soulauth/oidc-signing.pem
chmod 600 /etc/soulauth/oidc-signing.pem
# 然后设置 OIDC_RSA_PRIVATE_KEY_PATH=/etc/soulauth/oidc-signing.pem
```

未配置时进程启动会临时生成一把并打 WARN —— 重启后 `kid` 变化，已签发的 ID Token
将无法验签，依赖方会出现随机的登录失败。

## 权限系统说明

权威清单是 `contracts/permissions.yaml`，由 `tests/conformance.rs::j1` 双向对账：
注册表声明的每一条 Runtime 必须真的校验，Runtime 校验的每一条注册表必须声明；
角色的授予图也与 `initial_data.sql` 逐条比对。下面的表从那份契约抄来。

### 系统角色

| 角色 | 持有 |
|---|---|
| `admin` | 全部 14 条 |
| `security_manager` | `security.read`、`security.write`、`users.read` |
| `user_manager` | `users.read`、`users.write` |
| `auditor` | `audit.read` |
| `user` | 无。基线角色，不持有任何控制平面权限 |

### 系统权限

权限名带 `soulauth:` 前缀，划的是边界：这些权限只管 SoulAuth 自己的管理后台，
接入方系统很可能也有一个 `users.read`，两者同名不同物。

| 权限名 | 用于 |
|---|---|
| `soulauth:users.read` | 读主体、他人档案与偏好、他人活动日志 |
| `soulauth:users.write` | 改账号状态、改会员等级 |
| `soulauth:roles.read` | 列出与读取角色 |
| `soulauth:roles.write` | 建/改角色；给主体授予与撤销角色 |
| `soulauth:roles.delete` | 删除角色 |
| `soulauth:permissions.read` | 列出与读取权限 |
| `soulauth:permissions.write` | 建权限；在角色上挂载与摘除 |
| `soulauth:security.read` | 读锁定状态、安全指标、系统健康 |
| `soulauth:security.write` | **解除账号与 IP 锁定** |
| `soulauth:audit.read` | 审计看板、活动摘要、安全报告、他人活动日志 |
| `soulauth:oidc_clients.read` | 列出与读取 OIDC 客户端 |
| `soulauth:oidc_clients.write` | 注册 / 改 / 停用客户端；重新生成密钥 |
| `soulauth:actors.read` | 查看已注册的非人主体及其凭证 |
| `soulauth:actors.write` | 注册非人主体，增加或吊销其凭证 |

`oidc_clients.write` 是接入其它应用时要用的：注册客户端需要一个持有它的账号。

`actors.write` 与其它写权限不同 —— 别的改的是已有对象，这一条**能凭空造出一个
可认证的主体**。授出去之前想清楚。

## 应用程序部署

### 0. 前提：本服务是纯 API，需要配套前端

SoulAuth 不含任何页面，但**假定前端存在**。下列地址都指向 `APP_URL` 下的路径，
没有对应页面时用户点开就是 404：

| 场景 | 默认地址 | 可覆盖 |
|---|---|---|
| 邮箱验证信里的链接 | `{APP_URL}/verify-email?token=…` | `VERIFY_EMAIL_PAGE_URL` |
| 密码重置信里的链接 | `{APP_URL}/reset-password/{token}` | — |
| `/api/oidc/authorize` 未登录时跳转 | `{APP_URL}/login?return_to=…` | `LOGIN_PAGE_URL` |
| OAuth 登录成功后跳转（已有密码） | `{APP_URL}/oauth/callback` | — |
| OAuth 登录成功后跳转（无密码，需设首个密码） | `{APP_URL}/initialize-password` | — |

后三个目前是写死的路径，只能通过让前端在 `APP_URL` 下提供这些路由来满足。

### 1. 环境变量配置

**必填只有四项**（缺任一进程起不来）：

```env
JWT_SECRET=<至少 32 字符>
APP_URL=https://auth.example.com
SMTP_HOST=smtp.example.com
SMTP_FROM=noreply@example.com
```

`APP_URL` 是对外地址，不是监听地址。它决定三件事，填错的后果在 §「作为 OIDC
Provider」里展开：OIDC `issuer`、邮件里链接的前缀、cookie 是否带 `Secure`。

#### 生产环境额外必填（非环回 `APP_URL` 时强制）

`APP_URL` 的主机不是 `127.0.0.1` / `localhost` / `[::1]` 时，下面两项缺失
**直接拒绝启动**：

```env
OIDC_RSA_PRIVATE_KEY_PATH=/etc/soulauth/oidc-signing.pem   # 或 _PEM 直接给内容
MFA_SECRET_ENCRYPTION_KEY=<openssl rand -base64 32>
```

为什么是拒绝启动而不是警告：**这两项的后果都不在启动时显现**。

- 缺签名私钥 → 每次启动临时生成一把，**进程一重启，已签发的 ID Token 全部
  无法验签**；多副本部署里各副本各签各的，从第一天起就互不认账，
  表现为随机登录失败。
- 缺 MFA 密钥 → 从 `JWT_SECRET` 派生，**哪天轮换 `JWT_SECRET`，所有已存的
  TOTP 密钥变成无法解密**，全体 MFA 用户被锁在门外。

等它自己暴露的时候已经是线上事故。本地开发仍然放行——否则这道闸门会被人用
环境变量绕过去。

#### 数据库

```env
DATABASE_URL=127.0.0.1:8000        # 默认 http://localhost:8000；写 https:// 即走 TLS
DATABASE_USER=root
DATABASE_PASS=root
DATABASE_NAMESPACE=auth            # 默认 auth
DATABASE_NAME=main                 # 默认 main
DATABASE_CONNECTION_TIMEOUT=30
```

**关于数据库链路加密**：`DATABASE_URL` 带 `https://` 前缀即用 TLS 连接器，
否则走明文。指向非环回地址却用明文时，启动日志会给出一条 WARN —— 那条链路上
跑的是数据库口令、密码哈希与会话令牌。放在受信私有网段里可以接受，
跨网段务必用 https。

> 早期版本无论写不写 `https://` 都只用明文连接器（scheme 会被剥掉后丢弃），
> 且没有任何提示。若你此前配的是 `https://`，请确认数据库侧确实启用了 TLS。

#### 网络与前端

```env
BIND_ADDR=0.0.0.0:8080             # 监听地址，默认 0.0.0.0:8080
CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
TRUST_PROXY_HEADERS=true           # 在反向代理后必须开，否则限流按代理 IP 计数
LOGIN_PAGE_URL=                    # 默认 {APP_URL}/login
VERIFY_EMAIL_PAGE_URL=             # 默认 {APP_URL}/verify-email
```

`CORS_ALLOWED_ORIGINS` 留空时回落到 `APP_URL` 自身。**不要**指望它是 `*`——
那等于任何站点都能带着用户的 `Authorization` 头调用本服务。

`TRUST_PROXY_HEADERS` 在反向代理后**必须开**：不开的话所有请求的来源 IP 都是
代理的 IP，限流与账号锁定会把全体用户算成同一个客户端——一个人被锁，所有人
一起被锁。反过来，**没有代理时绝不能开**：那样客户端可以自己伪造
`X-Forwarded-For` 绕过限流。

#### 第三方登录（可选，不配就是不启用）

```env
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
OAUTH_REDIRECT_URL=https://auth.example.com/api/auth/callback
```

只用邮箱密码登录的部署**不需要填任何一项**。未配置时
`GET /api/auth/login/google` 返回 **501「本部署未启用」**，而不是拿假凭证去
换令牌再吐一个看不懂的 OAuth 错误。

两条判定规则：

- **只配 id 不配 secret 算未配置**。只配一半比两个都不配更危险——它看起来是
  开着的。
- **配了任一 provider 就必须配 `OAUTH_REDIRECT_URL`**，否则拒绝启动。缺它时
  重定向 URI 会被拼成残缺地址，登录走到第一步才失败。

可选的端点覆盖（默认走官方端点）：

```env
GOOGLE_OAUTH_BASE_URL=
GITHUB_OAUTH_BASE_URL=https://ghe.example.com    # 自托管 GitHub Enterprise
```

覆盖时沿用该 provider 真实的路径形状，只换根地址：Google 是
`{base}/o/oauth2/v2/auth` · `/token` · `/oauth2/v2/userinfo`；GitHub 是
`{base}/login/oauth/{authorize,access_token}` 与 `{base}/api/v3/user[/emails]`
—— 后者正是 GitHub Enterprise 的约定。

**明文 http 只允许指向环回地址**，且不得带尾斜杠，否则拒绝启动：远端端点走
明文等于把 `client_secret` 与访问令牌交给链路上的任何人。

#### 账号锁定

```env
LOCKOUT_MAX_ATTEMPTS=5             # 连续失败多少次后锁定，必须 ≥1
LOCKOUT_DURATION_MINUTES=15        # 锁定多少分钟，必须 ≥1
LOCKOUT_RESET_WINDOW_MINUTES=60    # 多久没有新失败就清零计数
LOCKOUT_USER_ENABLED=true          # 账号维度
LOCKOUT_IP_ENABLED=true            # IP 维度
```

前两项为 0 会在启动时被拒绝：0 次尝试即锁定等于任何人一登录就被锁死，
0 分钟锁定等于没锁 —— 这两种都不是「更严格」，是把服务配坏。

**手工解锁**（需 `soulauth:security.write`，种子里授予 admin 与 security_manager）：

```bash
# 查状态
curl "$APP_URL/api/security/lockout?scope=user&identifier=user%40example.com" \
  -H "Authorization: Bearer $TOKEN"
# → {"is_locked":true,"remaining_lockout_seconds":812,…}

# 解锁（scope 取 user 或 ip；解锁是幂等的，本来没锁会返回 unlocked:false）
curl -X POST "$APP_URL/api/security/unlock" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scope":"user","identifier":"user@example.com"}'
# → {"unlocked":true}
```

用户维度的标识是**邮箱**：锁定计数在登录失败时按邮箱累加，那时还没有用户记录
可言 —— 不存在的邮箱同样会被计数，否则「有没有留下锁定记录」本身就成了
账号枚举信道。

每一次解锁都会写一条 `lockout_cleared` 审计（包括本来就没锁的空操作）。

#### 邮件

```env
SMTP_PORT=587                      # 默认 587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_INSECURE=false                # 仅本地测试用
EMAIL_VERIFICATION_ENABLED=false   # 开启后注册需先验证邮箱
```

**发信失败只记日志，不阻断请求。** 也就是说 SMTP 配错时，注册会成功而验证信
永远收不到，日志之外没有任何提示。上线后请实际走一遍注册确认收得到信。

#### 其它

```env
JWT_EXPIRATION=86400               # 会话与访问令牌有效期，秒，默认 1 天
PASSWORD_MIN_LENGTH=12
AUTH_SESSION_CACHE_TTL_SECONDS=5   # 0 = 每请求都校验会话
PROXY_ENABLED=false                # 出站 OAuth 请求走代理
PROXY_URL=
```

`AUTH_SESSION_CACHE_TTL_SECONDS` 是**多副本下的吊销延迟上限**：本实例的登出 /
改密 / 停用会立刻清缓存，其它副本最多滞后一个 TTL。设为 0 则吊销绝对即时，
代价是每个请求多两次查询。

### 1.1 反向代理与 TLS（生产必需）

**SoulAuth 自身不终结 TLS**，只监听明文 HTTP。生产部署必须在前面放一个终结
TLS 的反向代理（nginx / Caddy / ALB 均可）。

这不是可选项，有两个硬约束逼着它：

1. `APP_URL` 是 https 时，会话 cookie 才会带 `Secure`；
4. **接入 SoulSeedOS 时，OS 硬拒非 https 的 JWKS 地址**——它的 `HttpJwksProvider`
   直接检查 `https://` 前缀（明文取签名公钥 = 路径上任何人都能换掉信任根）。

nginx 最小片段：

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

配套把 `TRUST_PROXY_HEADERS=true` 打开，否则限流与锁定会把所有人算成同一个
客户端。

### 1.2 多副本部署

| 事项 | 要求 |
|---|---|
| OIDC 签名私钥 | **必须所有副本共用同一份**。各生成各的话，A 签的令牌 B 验不了，而依赖方缓存了 JWKS，表现是间歇性 401 |
| 限流 | 已跨副本合账（登录 / 注册 / 改密 / 验邮箱等敏感端点经数据库共享计数）。一般 API 仍按副本计数，不给热路径加数据库往返 |
| 账号锁定 | 存在数据库里，天然跨副本 |
| 会话吊销 | 最多滞后一个 `AUTH_SESSION_CACHE_TTL_SECONDS` |
| 限流计数表 | `rate_limit`，由后台任务定期清理，无需人工维护 |

⚠ **重启副本不会清空限流配额**——共享计数存在数据库里。这是它该有的性质
（重启不能当解封手段），但排查时容易误以为「重启了怎么还被限」。要手工解封
某个客户端，删对应的 `rate_limit` 行。

### 1.3 代理环境的一个坑

环境里设了 `HTTP_PROXY` / `HTTPS_PROXY` 时，**`NO_PROXY` 必须覆盖 SurrealDB
的地址**。SoulAuth 连数据库走的也是 HTTP，代理会劫持到 `127.0.0.1` 的连接，
而故障形态是「数据库连接超时」——病因与形态对不上，很难查。

```bash
export NO_PROXY=127.0.0.1,localhost,${DB_HOST}
```

### 2. 数据库账号

**现状：应用只支持以 root 身份连接数据库。** 代码里走的是
`surrealdb::opt::auth::Root`，没有 namespace / database 级登录的分支。
所以下面这件事**目前做不到**，写在这里是为了说清限制，不是操作指引：

> 为应用创建一个最小权限的库级用户，只给数据读写、不给 DDL。

这是一项已知的待办。在它落地之前，务实的做法是把风险挡在数据库之外：

- SurrealDB **只监听内网或 loopback**，不要暴露到公网；
- root 口令用强随机值，与其它服务不复用；
- `DATABASE_URL` 跨网段时写 `https://`（应用会按 scheme 选择 TLS 连接器；
  写明文指向非环回地址时启动日志会告警 —— 那条链路上跑的是数据库口令、
  密码哈希与会话令牌）。

顺带纠正一处历史错误：本节此前给的是
`CREATE USER ... PASSWORD` / `GRANT SELECT,... ON auth.* TO ...`，
那是 MySQL / PostgreSQL 语法，SurrealDB 不认。SurrealDB 的写法是
`DEFINE USER ... ON DATABASE ... PASSWORD ... ROLES OWNER|EDITOR|VIEWER`，
但如上所述，当前的应用代码还用不了这种账号。

### 3. 部署步骤

1. **启动 SurrealDB** 并确认可达：
   ```bash
   surreal start --bind 127.0.0.1:8000 --user root --pass "$DB_PASS" \
     surrealkv:///var/lib/surrealdb/soulauth.db
   curl -f http://127.0.0.1:8000/health && echo " SurrealDB OK"
   ```

2. **准备环境变量**。四项必填，生产环境再加两项（见 §1）：
   ```bash
   export DATABASE_URL=127.0.0.1:8000
   export DATABASE_NAMESPACE=auth      # 下一步导入时必须用同一个值
   export DATABASE_NAME=main           # 同上
   export DATABASE_USER=root
   export DATABASE_PASS="$DB_PASS"
   export JWT_SECRET=$(openssl rand -hex 32)
   export APP_URL=https://auth.example.com
   export SMTP_HOST=smtp.example.com
   export SMTP_FROM=noreply@example.com
   export OIDC_RSA_PRIVATE_KEY_PATH=/etc/soulauth/oidc-signing.pem
   export MFA_SECRET_ENCRYPTION_KEY=$(openssl rand -base64 32)
   ```

3. **准备数据库**。注意这里直接复用上一步导出的变量，
   保证导入目标与应用启动后连接的是同一个 ns/db：
   ```bash
   surreal import --endpoint "http://$DATABASE_URL" \
       --user "$DATABASE_USER" --pass "$DATABASE_PASS" \
       --namespace "$DATABASE_NAMESPACE" --database "$DATABASE_NAME" schema.sql

   surreal import --endpoint "http://$DATABASE_URL" \
       --user "$DATABASE_USER" --pass "$DATABASE_PASS" \
       --namespace "$DATABASE_NAMESPACE" --database "$DATABASE_NAME" initial_data.sql
   ```

4. **构建应用程序**：
   ```bash
   cargo build --release
   ```

5. **启动应用程序**：
   ```bash
   ./target/release/soulauth
   ```

6. **验证部署**：
   ```bash
   curl http://localhost:8080/health
   # → {"status":"ok","uptime_seconds":12}
   ```

7. **建立第一个管理员**：

   全程不需要碰数据库。新实例在启动日志里打一枚一次性引导令牌（`WARN` 级别，
   默认日志级别下可见），用它换第一个管理员：

   ```bash
   # ① 从启动日志里取令牌
   #    WARN No administrator found. Bootstrap token for this process: 7f3a…
   #
   #    多副本部署时用 SOULAUTH_BOOTSTRAP_TOKEN 固定它；设为空串则完全
   #    关闭这条路径。

   # ② 用它建管理员。密码需满足策略：至少 12 个字符（PASSWORD_MIN_LENGTH），
   #    且含大写 / 小写 / 数字 / 符号四类中的三类
   curl -X POST http://localhost:8080/api/bootstrap/admin \
     -H 'Content-Type: application/json' \
     -d '{"token":"7f3a…","email":"admin@your-domain.com",
          "username":"admin","password":"CorrectHorse42!"}'
   # → {"user_id":"…","email":"admin@your-domain.com","is_admin":true}

   # ③ 登录拿会话令牌（引导响应里不含令牌）
   curl -X POST http://localhost:8080/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"admin@your-domain.com","password":"CorrectHorse42!"}'

   # ④ 确认权限已生效
   curl http://localhost:8080/api/auth/me -H "Authorization: Bearer <token>"
   # → "is_admin": true
   ```

   这道门是一次性的：系统里一旦存在管理员，端点永久拒绝，且对「令牌错」与
   「门已关」返回**逐字相同**的响应 —— 一枚失效令牌因此无法用来探测某个实例
   是否已经初始化。

   令牌是**这个进程**的（日志原话 `for this process`）：重启一次就换一枚，
   得回去看新的那行 `WARN`。

### 4. 验证这份文档本身

`tests/deployment_walkthrough.sh` 会照上面 §3 的步骤 1-7 从零跑一遍，
最后断言拿到一个 `is_admin: true` 的管理员：

```bash
cargo build && ./tests/deployment_walkthrough.sh
```

改动本文档的部署步骤后请一并跑它。参数名写错、ns/db 三处不一致这类问题，
只有真正执行才会暴露。

## 作为 OIDC Provider 接入（SoulSeedOS / 其它应用）

SoulAuth 既能独立使用，也能给别的系统当 OIDC Provider——**是同一套东西，
不需要模式开关**。接入方只是又一个注册的 OIDC 客户端。

### 谁做什么

以 SoulSeedOS 为例，三个角色的分工必须先说清，否则 `redirect_uris` 会填错：

| 组件 | 做什么 | 需要 `client_secret` 吗 |
|---|---|---|
| **BFF**（前端的服务端伴随组件） | 走完授权码流程：跳转 → 收回调 → 用 code 换 ID Token → 持有 refresh token 续期 | **是** |
| **SoulSeedOS** | 只用 JWKS 公钥验 ID Token 的签名与 `iss`/`aud`/`exp`/`sid` | 否，它从不出站换令牌 |
| 浏览器 | 拿着 BFF 给的 ID Token 调用 OS | 否 |

由此推出两条容易踩的：

- **`redirect_uris` 填 BFF 的回调地址，不是 OS 的。** OS 从头到尾不参与授权码
  交换。填错的表现是：登录跳转正常、用户认证成功、**回调那一步报
  `redirect_uri` 不匹配**——症状出现在回调环节而不是配置环节。
- **交给 OS 的必须是 ID Token，不是 access token。** SoulAuth 的 access token
  是 32 位不透明随机串，没有签名也没有 claim，OS 拿到它只会验签失败返回 401
  ——而这个 401 与「令牌过期」「issuer 配错」长得一模一样。

### 纯 SPA 不能直接接

浏览器里的代码无法安全持有 `client_secret`，也不适合长期保管 refresh token。
且 ID Token 被硬夹在 300 秒（见下），意味着持有方必须能在 5 分钟内续期——
这个上限本身就假定了有一个服务端会话持有者。

所以纯前端场景需要补一个 BFF，而不是把客户端注册成 `public` 了事。

### 注册客户端

需要一个持有 `soulauth:oidc_clients.write` 的账号（`admin` 角色有）。

```bash
curl -X POST https://auth.example.com/api/oidc/clients \
  -H "Authorization: Bearer <管理员令牌>" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "SoulSeedOS BFF",
    "client_type": "confidential",
    "redirect_uris": ["https://bff.example.com/auth/callback"],
    "require_pkce": true,
    "allowed_grant_types": ["authorization_code", "refresh_token"],
    "allowed_response_types": ["code"],
    "allowed_scopes": ["openid"],
    "id_token_lifetime": 300
  }'
```

⚠ **`client_secret` 只在创建响应里返回这一次**，之后查询客户端得到的是 `***`
掩码。丢了只能调 `POST /api/oidc/clients/:client_id/regenerate-secret` 重新
生成，而重新生成会让正在用旧 secret 的组件**立刻失效**。这一步没有便宜的重来，
注册前先把回调地址定下来。

⚠ **`id_token_lifetime` 传大于 300 的值会被静默夹到 300，不报错。** 直接填 300，
不要以为参数被忽略了。

### 接入方需要的三项参数

```text
issuer    = APP_URL 去掉尾斜杠      # 照抄发现文档的 issuer 字段最稳妥
jwks_uri  = {APP_URL}/api/oidc/jwks # 必须 https
client_id = 注册响应里的 client_id
```

`issuer` 与接入方配置的值必须**逐字一致**——尾斜杠、`www` 前缀、端口号，
差一个字符就全量 401。

### 客户端认证的两种方式

发现文档声明支持 `client_secret_post` 与 `client_secret_basic`，两种都可用：

```bash
# ① client_secret_post —— 凭证放表单
curl -X POST https://auth.example.com/api/oidc/token \
  -d grant_type=authorization_code -d code=... -d redirect_uri=... \
  -d client_id=... -d client_secret=... -d code_verifier=...

# ② client_secret_basic —— 凭证放 Authorization 头（多数 OIDC 客户端库的默认）
curl -X POST https://auth.example.com/api/oidc/token \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d grant_type=authorization_code -d code=... -d redirect_uri=... \
  -d code_verifier=...
```

走 Basic 时表单里**不必**再带一份 `client_id` —— 按 RFC 6749 §4.1.3，客户端已经
向授权服务器认证过时它不是必需的。带了也行，但必须与头里的一致，否则以
`invalid_client` 拒掉。两处都不给时返回 `invalid_request`。

**两处同时带凭证会被拒**（`invalid_request`），不会"挑一个用" —— 那会让
「两处 secret 不一致」这种明显异常被静默接受。

### 接入方必须知道的三条行为

这三条不看源码不可能知道，而踩中任何一条，症状都出现在离病因很远的地方。

**① 复用 refresh token 会打掉整个会话，不只是那一次失败**

刷新令牌是**一次性**的，每次刷新返回新的。重复使用已轮换的旧令牌被视为令牌
泄露信号，SoulAuth 会**吊销该用户在该客户端上的全部令牌**——用户被登出。

对 BFF 的含义：**因超时重试而重放同一个 refresh token 的代价是用户掉线**。
所以刷新必须按会话串行化，不能并发刷、不能盲目重试。网络超时时应先确认上一次
是否已经成功，而不是直接重发。

**② 客户端认证失败不消耗授权码**

`client_secret` 配错时，改对后用同一个 code 仍能换成功。错误处理可以按
「改配置后重试」写，不必让用户重新走一遍登录。

**③ `/api/oidc/authorize` 认的是浏览器会话 cookie，不是 Bearer**

BFF 把用户重定向到授权端点时，用户得先有 SoulAuth 的登录态；没有的话会被
引导到 `LOGIN_PAGE_URL`（默认 `{APP_URL}/login`）并带上 `return_to`。
登录页需要：调 `POST /api/auth/login` 完成登录，然后跳回 `return_to`。

### 接入后的验证顺序

每一步都能独立证伪，不用等到最后：

```bash
# ① issuer 是你要的那个
curl -s https://auth.example.com/.well-known/openid-configuration | jq -r .issuer

# ② JWKS 走 https 能取到，且有 kid
curl -s https://auth.example.com/api/oidc/jwks | jq -r '.keys[0].kid'

# ③ 走一次完整登录，把 ID Token 拆开看三项
echo "$ID_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iss, aud, sid, exp}'
```

第 ③ 步：`aud` 必须等于接入方配的 `client_id`，`iss` 必须逐字等于接入方配的
`issuer`，`sid` 必须非空。三项对上，接入方那侧就不会有意外。

⚠ SoulAuth 在取不到认证会话引用时**拒签**，不会签发缺 `sid` 的 ID Token。
所以 `sid` 为空只可能是拿错了令牌（把 access token 当成 ID Token 用）。

## 安全考虑

### 1. 数据库安全
- ✅ 应用程序只有DML权限，无DDL权限
- ✅ 数据库schema通过专门的迁移管理
- ✅ 避免了运行时表结构变更的风险

### 2. 权限管理
- ✅ 系统角色受保护，不可删除
- ✅ 权限检查在API级别进行
- ✅ 支持细粒度权限控制

### 3. 部署安全
- ✅ 环境变量管理敏感信息
- ✅ 分离的数据库用户权限
- ✅ 明确的初始化流程

## 维护和更新

### Schema变更
如果需要修改数据库结构：

1. 创建新的迁移SQL文件
2. 在维护窗口期间执行迁移
3. 更新应用程序代码
4. 重新部署应用程序

### 添加新权限
如果需要添加新的系统权限：

1. 在 `initial_data.sql` 中添加新权限
2. 更新相应的角色权限分配
3. 执行增量SQL更新

### 监控
建议监控以下指标：
- 数据库连接状态
- API响应时间
- 权限检查失败次数
- 登录失败和账户锁定事件

## 故障排除

### 常见问题：症状与病因对不上的几类

下面几条的共同点是**故障形态指向了错误的方向**，按症状去查会白花时间。

| 症状 | 实际原因 |
|---|---|
| 数据库连接超时 | 环境里有 HTTP 代理，劫持了到 `127.0.0.1` 的连接。`NO_PROXY` 加上数据库地址 |
| 一个人被限流，所有人一起被限 | 在反向代理后没开 `TRUST_PROXY_HEADERS`，所有请求的来源 IP 都是代理的 |
| 重启了服务，限流还在 | 敏感端点的限流计数存在数据库里，重启不清（设计如此）。删对应的 `rate_limit` 行 |
| 注册成功但收不到验证信 | 发信失败只记日志、不阻断请求。查应用日志里的 SMTP 错误 |
| 接入方间歇性 401 | 多副本各自生成了临时 OIDC 私钥。配 `OIDC_RSA_PRIVATE_KEY_PATH` 并让所有副本共用 |
| 接入方稳定 401，且 `sid` 为空 | 拿的是 access token（32 位不透明串）不是 ID Token |
| 登录跳转正常，回调报 `redirect_uri` 不匹配 | 注册客户端时 `redirect_uris` 填成了资源服务器的地址，应填执行授权码交换那一方的回调地址 |
| 用户莫名被登出 | refresh token 被重放（如超时后重试）。刷新必须按会话串行化 |
| 轮换 `JWT_SECRET` 后 MFA 全体失效 | 未单独配 `MFA_SECRET_ENCRYPTION_KEY`，密钥从 `JWT_SECRET` 派生 |

### 其它常见问题

3. **应用启动失败**：
   - 检查数据库连接配置
   - 确认数据库表已创建
   - 检查环境变量设置

4. **权限检查失败**：
   - 确认用户已分配正确角色
   - 检查角色权限配置
   - 验证系统权限是否正确初始化

5. **数据库连接问题**：
   - 检查数据库服务状态
   - 验证连接字符串
   - 确认网络连通性

通过遵循这个部署指南，您可以安全、可靠地部署Rust Auth System到生产环境。