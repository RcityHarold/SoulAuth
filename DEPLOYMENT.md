# Rust Auth System 部署指南

本文档说明如何正确部署 Rust Auth System 到生产环境。

## 数据库部署

### 1. 创建数据库表结构

在启动应用程序之前，必须先运行以下SQL文件来创建数据库表结构：

```bash
# 连接到 SurrealDB
surreal sql --conn http://localhost:8000 --user root --pass root --ns production --db auth

# 导入表结构
surreal import --conn http://localhost:8000 --user root --pass root --ns production --db auth schema.sql

# 或者手动执行SQL文件内容
```

**重要说明**：
- `schema.sql` 包含所有必需的数据库表定义
- 必须在应用程序启动前执行此文件
- 这样设计符合生产环境最佳实践，避免应用程序具有DDL权限

### 2. 初始化系统数据

创建完表结构后，运行初始数据文件来创建系统角色和权限：

```bash
# 导入初始数据
surreal import --conn http://localhost:8000 --user root --pass root --ns production --db auth initial_data.sql

# 或者手动执行SQL文件内容
```

**`initial_data.sql` 包含的内容**：
- 系统权限（12个基础权限）
- 系统角色（5个预定义角色）
- 系统用户账户（用于权限分配的内部账户）
- 角色权限关联（为系统角色分配适当的权限）

### 3. 安装文档系统权限（可选）

如果需要集成 Rainbow-Docs 文档系统，请运行额外的权限扩展文件：

```bash
# 导入文档系统权限
surreal import --conn http://localhost:8000 --user root --pass root --ns production --db auth docs_permissions.sql

# 或者手动执行SQL文件内容
```

**`docs_permissions.sql` 包含的内容**：
- 文档管理权限（10个文档相关权限）
- 文档系统角色（3个文档专用角色）
- 权限关联（为现有角色分配文档权限）

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

3. **补充 user 表字段：**
   ```sql
   DEFINE FIELD verification_token_expires_at ON user TYPE option<number>;
   ```

4. **`oidc_client.created_by` 字段类型由 `record<user>` 改为 `string`。**
   存量行里存的是 record 链接，必须**先转换数据、再改字段定义**，否则改完之后
   读取旧行会直接失败：
   ```sql
   -- ① 先把已有的 record 链接转成字符串
   UPDATE oidc_client SET created_by = type::string(created_by)
     WHERE created_by != NONE;
   -- ② 再收紧字段类型
   DEFINE FIELD created_by ON oidc_client TYPE string;
   ```

5. **社交相关表已不再使用**，可在确认无其他消费方后删除：
   `friend_request`、`friendship`、`direct_conversation`、`direct_message`、
   `social_group`、`social_group_member`、`group_thread`、`group_thread_message`、
   `group_collab_run`。

6. **新增必填 / 建议配置：** `CORS_ALLOWED_ORIGINS`、`TRUST_PROXY_HEADERS`、
   `OIDC_RSA_PRIVATE_KEY_PATH`。`JWT_SECRET` 现在要求至少 32 字符。

7. **应用不再自动建表。** 启动时的 DDL 已移除，schema 变更一律通过 `schema.sql`
   手动执行——这与本文档开头"应用程序不应具有 DDL 权限"的原则一致。

8. **已注册的 OIDC 客户端密钥仍可用**（旧的 SHA-256 哈希会继续被接受），
   但建议逐个调用 `POST /api/oidc/clients/:client_id/regenerate-secret`
   迁移到 Argon2 存储。

9. **配置 MFA 密钥加密密钥。** TOTP 密钥现在加密后落库：
   ```bash
   openssl rand -base64 32   # 填入 MFA_SECRET_ENCRYPTION_KEY
   ```
   不配置时会从 `JWT_SECRET` 派生并打 WARN —— 那样一来轮换 `JWT_SECRET`
   会导致所有已存的 TOTP 密钥无法解密，生产环境务必单独配置。
   存量的明文密钥可继续使用，并在下一次写入时自动就地加密。

10. **备用恢复码改为 Argon2 哈希存储。** 升级前生成的明文备用码仍可校验，
    但建议让已启用 MFA 的用户重新生成一次（`POST /api/auth/mfa/setup`）。

11. **`initial_data.sql` / `docs_permissions.sql` 现在是幂等的**（`CREATE` 全部
    改为带确定性 ID 的 `UPSERT`），可以安全地重复执行。

12. **`/api/oidc/authorize` 的未登录跳转目标变了。** 以前直接 302 到 Google，
    现在跳 `LOGIN_PAGE_URL`（默认 `{APP_URL}/login`）并带 `return_to`。
    登录页需要做两件事：调用 `POST /api/auth/login` 完成登录，
    然后跳回 `return_to` 指向的地址；如果仍需要 Google 登录入口，
    在页面上链到 `GET /api/auth/login/google` 即可。

13. **本地开发不再需要 https。** Cookie 的 `Secure` 属性现在由 `APP_URL` 的协议
    决定，`http://localhost:8080` 下会自动省略。

14. **可选：调整 `AUTH_SESSION_CACHE_TTL_SECONDS`。** 默认 5 秒。设为 0 会回到
    每个请求都校验会话（吊销绝对即时，代价是每请求两次查询）。

15. **必须重新执行 `schema.sql` 中的这几条字段定义**（类型有变，且 SCHEMAFULL
    下旧定义会拒绝新写入）：
    ```sql
    -- 审计事件未必对应已存在的用户（登录失败、限流触发等）
    DEFINE FIELD user_id ON user_activity TYPE option<record<user>>;
    ```
    如果 `user_activity` / `user_profile` / `user_preferences` 里已有历史数据，
    由于此前的写入本就会被 SCHEMAFULL 拒绝，这些表大概率是空的；若确有数据，
    需要把 datetime 值转成 Unix 秒后再启用新版本。

16. **所有用户需要重新登录（第二次）。** 浏览器会话 cookie 现在必须携带 `sid`
    并对应一条有效的 `session` 记录，升级前签发的 cookie 会被拒绝。

17. **前端需要新增一个邮箱验证页**（或配置 `VERIFY_EMAIL_PAGE_URL` 指向已有页面）：
    验证邮件的链接现在是 `{VERIFY_EMAIL_PAGE_URL}?token=xxx`，页面拿到 token 后
    再调 `GET /api/auth/verify-email/{token}`。

18. **审计接口的响应结构有两处变化：**
    - `GET /api/audit/system-health` 删除了 `connection_pool_used` /
      `connection_pool_size` 两个字段（SurrealDB HTTP 客户端不暴露连接池指标，
      之前一直是写死的 1/10）；内存与运行时长改为真实值。
    - `GET /api/audit/security-report` 中 `user_retention_metrics` 的字段
      由 `daily_retention` / `weekly_retention` / `monthly_retention` 改名为
      `daily_active_rate` / `weekly_active_rate` / `monthly_active_rate`
      —— 这个口径本来就是活跃率而非留存率。同一接口的
      `geographic_distribution` 现在恒为空数组（没有接入 GeoIP 数据源）。

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

| 权限名 | 资源 | 操作 | 描述 |
|--------|------|------|------|
| `users.read` | users | read | 查看用户信息 |
| `users.write` | users | write | 编辑用户信息 |
| `users.delete` | users | delete | 删除用户账户 |
| `roles.read` | roles | read | 查看角色信息 |
| `roles.write` | roles | write | 管理角色 |
| `roles.delete` | roles | delete | 删除角色 |
| `permissions.read` | permissions | read | 查看权限信息 |
| `permissions.write` | permissions | write | 管理权限 |
| `permissions.delete` | permissions | delete | 删除权限 |
| `security.read` | security | read | 查看安全状态 |
| `security.write` | security | write | 管理安全操作 |
| `audit.read` | audit | read | 查看审计日志 |

### 文档系统权限（可选）

如果安装了文档系统权限扩展，还包含以下权限：

| 权限名 | 资源 | 操作 | 描述 |
|--------|------|------|------|
| `docs.read` | documents | read | 查看和阅读文档内容 |
| `docs.write` | documents | write | 创建、编辑和发布文档 |
| `docs.delete` | documents | delete | 删除文档和章节 |
| `docs.admin` | documents | admin | 管理文档空间、权限和设置 |
| `spaces.read` | spaces | read | 查看和访问文档空间 |
| `spaces.write` | spaces | write | 创建、编辑文档空间和设置 |
| `spaces.delete` | spaces | delete | 删除文档空间 |
| `comments.read` | comments | read | 查看文档评论和讨论 |
| `comments.write` | comments | write | 添加、编辑和回复评论 |
| `comments.delete` | comments | delete | 删除评论和讨论 |

### 文档系统角色（可选）

| 角色名 | 显示名称 | 描述 | 权限范围 |
|--------|----------|------|----------|
| `docs_admin` | 文档管理员 | 拥有完整文档管理权限 | 所有文档权限 |
| `docs_editor` | 文档编辑员 | 可以创建和编辑文档 | docs.read, docs.write, comments |
| `docs_reader` | 文档阅读者 | 只能查看文档 | docs.read, spaces.read, comments.read |

## 应用程序部署

### 1. 环境变量配置

确保设置所有必需的环境变量：

```env
# 数据库配置
DATABASE_URL=http://localhost:8000
DATABASE_USER=your-db-user
DATABASE_PASS=your-db-password
DATABASE_CONNECTION_TIMEOUT=30
DATABASE_MAX_CONNECTIONS=10

# JWT配置 (必需)
JWT_SECRET=your-super-secure-jwt-secret-key-here
JWT_EXPIRATION=86400

# OAuth配置 (可选)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
OAUTH_REDIRECT_URL=https://your-domain.com/api/auth/callback

# SMTP配置
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password
SMTP_FROM=noreply@your-domain.com

# 应用配置
APP_URL=https://your-domain.com
```

### 2. 数据库权限

为应用程序创建专用的数据库用户，只授予必要的权限：

```sql
-- 创建应用程序专用用户
CREATE USER app_user ON DATABASE auth PASSWORD 'secure-password';

-- 授予必要的数据权限（不包括DDL权限）
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.* TO app_user;

-- 不要授予CREATE, DROP, ALTER等DDL权限
```

### 3. 部署步骤

1. **准备数据库**：
   ```bash
   # 1. 执行schema.sql创建表结构
   surreal import --conn $DATABASE_URL --user root --pass root --ns $NAMESPACE --db $DATABASE schema.sql
   
   # 2. 执行initial_data.sql创建初始数据
   surreal import --conn $DATABASE_URL --user root --pass root --ns $NAMESPACE --db $DATABASE initial_data.sql
   ```

2. **构建应用程序**：
   ```bash
   cargo build --release
   ```

3. **启动应用程序**：
   ```bash
   ./target/release/rust-auth
   ```

4. **验证部署**：
   ```bash
   # 检查健康状态
   curl http://localhost:8080/health
   
   # 创建第一个管理员用户
   curl -X POST http://localhost:8080/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@your-domain.com","password":"secure-password"}'
   ```

5. **分配管理员权限**：
   ```bash
   # 登录获取JWT token
   curl -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@your-domain.com","password":"secure-password"}'
   
   # 手动为第一个用户分配admin角色（通过数据库）
   # 或者使用系统管理界面
   ```

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

### 常见问题

1. **应用启动失败**：
   - 检查数据库连接配置
   - 确认数据库表已创建
   - 检查环境变量设置

2. **权限检查失败**：
   - 确认用户已分配正确角色
   - 检查角色权限配置
   - 验证系统权限是否正确初始化

3. **数据库连接问题**：
   - 检查数据库服务状态
   - 验证连接字符串
   - 确认网络连通性

通过遵循这个部署指南，您可以安全、可靠地部署Rust Auth System到生产环境。