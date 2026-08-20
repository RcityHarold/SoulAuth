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

### 3. 清理 Rainbow-Docs 遗留权限（仅存量实例需要）

`docs_permissions.sql` 已删除。它曾往 SoulAuth 的权限表里塞入另一个项目
（Rainbow-Docs）的 10 个权限、3 个角色和 31 条授权关联，而 SoulAuth 自身代码
从未引用过它们 —— 按 P0-DECISION-09/10，Auth-local RBAC 只管 SoulAuth 自己的
管理后台，别的应用的权限不该寄存在这里。

全新部署无需任何操作。**已经导入过该文件的实例**，其数据库里仍留有这些行，
需手工清理（先删关联再删主体，避免留下孤儿关联）：

```sql
-- 1) 先删授权关联
DELETE role_permission WHERE permission_id IN (
    SELECT VALUE id FROM permission
    WHERE string::starts_with(name, 'soulauth:docs.')
       OR string::starts_with(name, 'soulauth:spaces.')
       OR string::starts_with(name, 'soulauth:comments.')
);
DELETE role_permission WHERE role_id IN (
    SELECT VALUE id FROM role WHERE name IN ['docs_admin', 'docs_editor', 'docs_reader']
);

-- 2) 再删权限与角色本体
DELETE permission WHERE string::starts_with(name, 'soulauth:docs.')
    OR string::starts_with(name, 'soulauth:spaces.')
    OR string::starts_with(name, 'soulauth:comments.');
DELETE role WHERE name IN ['docs_admin', 'docs_editor', 'docs_reader'];

-- 3) 顺带清掉可能残留的用户-角色绑定
DELETE user_role WHERE role_id NOT IN (SELECT VALUE id FROM role);
```

## OIDC 签名密钥

ID Token 使用 RS256 签名，公钥通过 `/api/oidc/jwks` 发布。生产环境必须提供一把持久私钥：

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /etc/soulauth/oidc-signing.pem
chmod 600 /etc/soulauth/oidc-signing.pem
# 然后设置 OIDC_RSA_PRIVATE_KEY_PATH=/etc/soulauth/oidc-signing.pem
```

未配置时进程启动会临时生成一把并打 WARN —— 重启后 `kid` 变化，已签发的 ID Token
将无法验签，依赖方会出现随机的登录失败。

## 从旧版本升级

1. **所有用户需要重新登录。** 现在每次鉴权都会核对 `session` 表，登出与改密可以
   真正吊销令牌；升级前签发的令牌若无对应会话记录将被拒绝。

2. **执行权限迁移。** `initial_data.sql` 末尾新增了 `oidc_clients.read` /
   `oidc_clients.write` 两个权限并授予 admin 角色。已有部署单独执行该段即可，
   否则管理员将无法访问 `/api/oidc/clients`。

3. **`membership_expiry` 由 `string` 改为 `datetime`。**

   该字段以前是自由字符串且写入不校验，`"下个月"` 这类值也能落库。
   现在由类型保证形状（语义仍不由 SoulAuth 解释，见
   P0-DECISION-09 §4.7）。**必须先清洗数据再改字段定义**，
   否则改完之后读取旧行会失败：

   ```sql
   -- ① 把无法解析的值清空（能解析的按 RFC3339 转换）
   UPDATE user SET membership_expiry = NONE
     WHERE membership_expiry != NONE
       AND type::is::datetime(<datetime> membership_expiry) = false;

   -- ② 再改字段定义
   DEFINE FIELD membership_expiry ON user TYPE option<datetime>;
   ```

4. **`AccountStatus` 移除了 `PendingDeletion` 变体。**

   它此前的行为与 `Deleted` 完全同义（没有宽限期、没有到期推进、
   没有级联清除、也没有撤销入口），却对外宣告了一条不存在的删除流水线。
   存量的 `"PendingDeletion"` 行会被解析成 `Inactive`（不可用），
   方向是 fail-closed、不会误放行；但建议显式归位：

   ```sql
   UPDATE user SET account_status = 'Deleted' WHERE account_status = 'PendingDeletion';
   ```

   `PUT /api/users/users/{id}/status` 从此拒收 `"PendingDeletion"`（400）。

5. **补充 user 表字段：**
   ```sql
   DEFINE FIELD verification_token_expires_at ON user TYPE option<number>;
   ```

6. **`oidc_client.created_by` 字段类型由 `record<user>` 改为 `string`。**
   存量行里存的是 record 链接，必须**先转换数据、再改字段定义**，否则改完之后
   读取旧行会直接失败：
   ```sql
   -- ① 先把已有的 record 链接转成字符串
   UPDATE oidc_client SET created_by = type::string(created_by)
     WHERE created_by != NONE;
   -- ② 再收紧字段类型
   DEFINE FIELD created_by ON oidc_client TYPE string;
   ```

7. **社交相关表已不再使用**，可在确认无其他消费方后删除：
   `friend_request`、`friendship`、`direct_conversation`、`direct_message`、
   `social_group`、`social_group_member`、`group_thread`、`group_thread_message`、
   `group_collab_run`。

8. **新增必填 / 建议配置：** `CORS_ALLOWED_ORIGINS`、`TRUST_PROXY_HEADERS`、
   `OIDC_RSA_PRIVATE_KEY_PATH`。`JWT_SECRET` 现在要求至少 32 字符。

9. **应用不再自动建表。** 启动时的 DDL 已移除，schema 变更一律通过 `schema.sql`
   手动执行——这与本文档开头"应用程序不应具有 DDL 权限"的原则一致。

10. **已注册的 OIDC 客户端密钥仍可用**（旧的 SHA-256 哈希会继续被接受），
   但建议逐个调用 `POST /api/oidc/clients/:client_id/regenerate-secret`
   迁移到 Argon2 存储。

11. **配置 MFA 密钥加密密钥。** TOTP 密钥现在加密后落库：
   ```bash
   openssl rand -base64 32   # 填入 MFA_SECRET_ENCRYPTION_KEY
   ```
   不配置时会从 `JWT_SECRET` 派生并打 WARN —— 那样一来轮换 `JWT_SECRET`
   会导致所有已存的 TOTP 密钥无法解密，生产环境务必单独配置。
   存量的明文密钥可继续使用，并在下一次写入时自动就地加密。

12. **备用恢复码改为 Argon2 哈希存储。** 升级前生成的明文备用码仍可校验，
    但建议让已启用 MFA 的用户重新生成一次（`POST /api/auth/mfa/setup`）。

13. **`initial_data.sql` 现在是幂等的**（`CREATE` 全部改为带确定性 ID 的
    `UPSERT`），可以安全地重复执行。权限名前缀化后，重跑它即可就地改名 ——
    `role_permission` 按 record ID 关联，角色授权关系不受影响。

14. **`/api/oidc/authorize` 的未登录跳转目标变了。** 以前直接 302 到 Google，
    现在跳 `LOGIN_PAGE_URL`（默认 `{APP_URL}/login`）并带 `return_to`。
    登录页需要做两件事：调用 `POST /api/auth/login` 完成登录，
    然后跳回 `return_to` 指向的地址；如果仍需要 Google 登录入口，
    在页面上链到 `GET /api/auth/login/google` 即可。

15. **本地开发不再需要 https。** Cookie 的 `Secure` 属性现在由 `APP_URL` 的协议
    决定，`http://localhost:8080` 下会自动省略。

16. **可选：调整 `AUTH_SESSION_CACHE_TTL_SECONDS`。** 默认 5 秒。设为 0 会回到
    每个请求都校验会话（吊销绝对即时，代价是每请求两次查询）。

17. **必须重新执行 `schema.sql` 中的这几条字段定义**（类型有变，且 SCHEMAFULL
    下旧定义会拒绝新写入）：
    ```sql
    -- 审计事件未必对应已存在的用户（登录失败、限流触发等）
    DEFINE FIELD user_id ON user_activity TYPE option<record<user>>;
    ```
    如果 `user_activity` / `user_profile` / `user_preferences` 里已有历史数据，
    由于此前的写入本就会被 SCHEMAFULL 拒绝，这些表大概率是空的；若确有数据，
    需要把 datetime 值转成 Unix 秒后再启用新版本。

18. **所有用户需要重新登录（第二次）。** 浏览器会话 cookie 现在必须携带 `sid`
    并对应一条有效的 `session` 记录，升级前签发的 cookie 会被拒绝。

19. **前端需要新增一个邮箱验证页**（或配置 `VERIFY_EMAIL_PAGE_URL` 指向已有页面）：
    验证邮件的链接现在是 `{VERIFY_EMAIL_PAGE_URL}?token=xxx`，页面拿到 token 后
    再调 `GET /api/auth/verify-email/{token}`。

20. **审计接口的响应结构有两处变化：**
    - `GET /api/audit/system-health` 删除了 `connection_pool_used` /
      `connection_pool_size` 两个字段（SurrealDB HTTP 客户端不暴露连接池指标，
      之前一直是写死的 1/10）；内存与运行时长改为真实值。
    - `GET /api/audit/security-report` 中 `user_retention_metrics` 的字段
      由 `daily_retention` / `weekly_retention` / `monthly_retention` 改名为
      `daily_active_rate` / `weekly_active_rate` / `monthly_active_rate`
      —— 这个口径本来就是活跃率而非留存率。同一接口的
      `geographic_distribution` 现在恒为空数组（没有接入 GeoIP 数据源）。

21. **第三方登录凭证由必填改为可选（破坏性变更的反面：放宽）。**
    `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` / `GITHUB_CLIENT_ID` /
    `GITHUB_CLIENT_SECRET` / `OAUTH_REDIRECT_URL` 五项此前是硬必填，只用邮箱
    密码登录的部署被迫填假值。现在不配即不启用，登录入口返回 501。
    **已填假值的实例建议清掉**——配置里的假数据一旦哪天被当真就是事故。

22. **生产环境缺密钥改为拒绝启动。** `APP_URL` 非环回时，缺
    `OIDC_RSA_PRIVATE_KEY_PEM`/`_PATH` 或 `MFA_SECRET_ENCRYPTION_KEY` 会让进程
    起不来（此前只打 WARN）。升级前请确认这两项已配，否则重启后服务不可用。
    理由见「生产环境额外必填」一节。

23. **限流改为跨副本合账。** 新增 `rate_limit` 表，需重新执行 `schema.sql`
    （或单独执行该表的 `DEFINE`）。登录 / 注册 / 改密 / 验邮箱等敏感端点的
    计数经数据库共享，多副本不再各算各的。
    ⚠ 副作用：**重启副本不再清空配额**。这是它该有的性质，但排查时容易误判。

24. **`client_secret_basic` 补上实现。** 此前发现文档声明支持它，而令牌端点
    只解析表单——用标准 OIDC 客户端库接入的机密客户端会失败，且错误信息
    指向「未提供 secret」。升级后两种方式都可用。

25. **账号状态判定改为白名单。** 只有 `Active` 放行，未知状态一律按不可用
    处理（此前是「没被显式列为坏的就算好的」）。若你的数据库里有非标准的
    `account_status` 值，那些账号升级后将无法登录——升级前先查：
    ```sql
    SELECT VALUE account_status FROM user
    WHERE account_status NOT IN ['Active','Inactive','Suspended','Deleted'];
    ```

## 权限系统说明

### 系统角色

| 角色名 | 显示名称 | 描述 | 权限范围 |
|--------|----------|------|----------|
| `admin` | 系统管理员 | 拥有所有权限 | 所有权限 |
| `user_manager` | 用户管理员 | 负责用户管理 | users.read, users.write, users.delete |
| `security_manager` | 安全管理员 | 负责安全管理 | security.read, security.write, users.read |
| `auditor` | 审计员 | 查看审计日志 | audit.read |
| `user` | 普通用户 | 基础用户角色 | 基础权限 |

### 系统权限

权限名带 `soulauth:` 命名空间前缀（P0-DECISION-10 DEC-10-05）。前缀的意义是
划清边界：这些权限只管 SoulAuth 自己的管理后台，**不是 SoulSeedOS 的
Canonical Permission Source** —— OS 侧也有 `users.read` 这类名字，两者同名不同物。

代码中真正被检查的是下面 11 个（单一真相在 `src/models/permission.rs`
的 `names` 模块，有单元测试守着它与 `initial_data.sql` 的一致性）：

| 权限名 | 用于 |
|---|---|
| `soulauth:users.read` | 读用户、他人资料/偏好、他人 SSO 会话 |
| `soulauth:users.write` | 改账号状态、改会员等级 |
| `soulauth:roles.read` | 读角色与角色权限 |
| `soulauth:roles.write` | 给用户授/撤角色 |
| `soulauth:roles.delete` | 删除角色 |
| `soulauth:permissions.read` | 读权限详情 |
| `soulauth:permissions.write` | 给角色授/撤权限 |
| `soulauth:security.read` | 安全指标、系统健康、全局会话统计、会话清理 |
| `soulauth:audit.read` | 审计看板、活动摘要、安全报告、他人活动日志 |
| `soulauth:oidc_clients.read` | 读 OIDC 客户端 |
| `soulauth:oidc_clients.write` | **注册 / 改 / 停用 OIDC 客户端** |

最后一条是接入 SoulSeedOS 时要用的——注册 OS 客户端需要一个持有它的账号。

`initial_data.sql` 另外还种了 7 个当前**没有任何代码引用**的权限
（`users.delete` / `permissions.delete` / `security.write` /
`profile.read` / `profile.write` / `preferences.read` / `preferences.write`）。
它们授给了 admin 与 user_manager，但不影响任何接口的判定——留着是为将来，
不要据此以为某个接口受它们保护。

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
   surreal start --bind 127.0.0.1:8000 --user root --pass "$DB_PASS" file:/var/lib/surrealdb
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

   注册接口本身不发管理员权限——第一个 admin 必须在库里手工授予，
   这是刻意的：否则"谁是第一个注册的人"就成了拿到全部权限的条件。

   ```bash
   # ① 注册。username 是必填项，密码需满足策略：
   #    至少 12 个字符，且含大写 / 小写 / 数字 / 符号四类中的三类
   curl -X POST http://localhost:8080/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@your-domain.com","username":"admin","password":"CorrectHorse42!"}'

   # ② 在数据库里把 admin 角色授予该账号
   curl -u "$DATABASE_USER:$DATABASE_PASS" \
     -H "surreal-ns: $DATABASE_NAMESPACE" -H "surreal-db: $DATABASE_NAME" \
     --data "LET \$u = (SELECT VALUE id FROM user WHERE email = 'admin@your-domain.com')[0];
             CREATE user_role CONTENT {
               user_id: \$u, role_id: role:admin,
               assigned_at: 0, assigned_by: user:system
             };" \
     "http://$DATABASE_URL/sql"

   # ③ 重新登录拿令牌（角色变更后需要重新登录，令牌本身不带角色）
   curl -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@your-domain.com","password":"CorrectHorse42!"}'

   # ④ 确认权限已生效
   curl http://localhost:8080/api/auth/me -H "Authorization: Bearer <token>"
   # → "is_admin": true
   ```

### 4. 验证这份文档本身

`tests/deployment_walkthrough.sh` 会照上面 §3 的步骤 1-7 从零跑一遍，
最后断言拿到一个 `is_admin: true` 的管理员：

```bash
cargo build && ./tests/deployment_walkthrough.sh
```

改动本文档的部署步骤后请一并跑它。这份文档曾经通不过自己 —— 参数名写错、
ns/db 三处不一致，而这些只有真正执行才会暴露。

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
  -d client_id=... -d code_verifier=...
```

**两处同时带凭证会被拒**（`invalid_request`），不会"挑一个用"——那会让
「两处 secret 不一致」这种明显异常被静默接受。

> **升级提示**：`client_secret_basic` 是 2026-08-17 才补上实现的。此前发现
> 文档一直声明支持它，而令牌端点只解析表单。跑更早版本的实例上，用标准
> OIDC 客户端库接入会报 `Client secret required for confidential clients`
> ——接入方会反复检查自己的配置，而配置是对的。

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
| 接入方报「未提供 client_secret」，但配置是对的 | 客户端库走的是 `client_secret_basic`，而实例版本早于 2026-08-17 |
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