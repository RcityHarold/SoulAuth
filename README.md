# Rust Auth System

一个使用 Rust 构建的现代化认证系统，支持多种认证方式和用户管理功能。

## 功能特点

### 用户认证
- 邮箱密码注册和登录
- Google OAuth 登录
- GitHub OAuth 登录
- JWT 令牌认证
- 邮箱验证
- 密码加密存储 (Argon2)
- 密码重置功能
- 安全会话管理

### 权限系统 🔐
- **RBAC (基于角色的访问控制)**: 完整的角色权限管理系统
- **角色管理**: 创建、编辑、删除角色，支持系统角色保护
- **权限管理**: 基于资源和操作的细粒度权限控制
- **用户角色分配**: 灵活的用户角色分配和移除
- **权限检查**: 实时权限验证和角色检查
- **系统角色**: 预定义管理员、用户管理员、安全管理员等角色
- **权限继承**: 角色权限自动继承和聚合
- **权限保护**: API接口级别的权限控制

### 用户生命周期管理 👤
- **完整用户档案管理**: 个人信息、联系方式、头像管理
- **账户状态控制**: Active、Inactive、Suspended、PendingDeletion、Deleted
- **用户偏好设置**: 主题、语言、通知设置、安全偏好
- **用户活动审计**: 详细操作日志、分类管理、查询过滤
- **管理员功能**: 用户列表管理、批量操作、状态变更
- **最后登录追踪**: 登录时间和IP地址记录
- **用户注册和验证**: 邮箱验证、OAuth用户管理
- **完整的会话管理**: 登录、登出、会话列表
- **密码重置和恢复**: 安全的重置流程
- **基于角色的用户权限管理**: 与RBAC系统完全集成

### 安全防护层 🛡️
- **速率限制 (Rate Limiting)**: 防止暴力破解和API滥用
- **多因素认证 (MFA)**: TOTP/Google Authenticator支持
- **账户锁定机制**: 多次失败登录后自动锁定账户
- **智能安全检查**: 基于IP和用户的双重保护
- **自动安全管理**: 过期记录清理和动态解锁

### 监控审计系统 📊
- **安全仪表板**: 实时安全指标概览和趋势分析
- **审计日志分析**: 用户活动分类统计和行为分析 
- **安全事件监控**: 失败登录、权限拒绝、可疑活动检测
- **系统健康监控**: 数据库状态、内存使用、连接池监控
- **安全报告生成**: 自动生成详细的安全分析报告
- **威胁检测**: 基于行为模式的异常活动识别
- **性能指标**: 认证成功率、锁定统计、速率限制违规
- **风险评估**: 自动风险级别计算和安全建议

### 安全增强功能
- 基于数据库的会话存储
- 会话主动失效（登出）
- 批量会话管理（全部登出）
- 防止邮箱枚举攻击
- 时效性密码重置令牌
- 安全的JWT密钥管理

### 🔐 OIDC 单点登录 (SSO) 🆕
- **OIDC 协议支持**: 完整的 OpenID Connect 1.0 协议实现
- **单点登录**: 支持跨应用的无缝身份验证
- **授权码流程**: 标准的 OAuth 2.0 授权码流程
- **PKCE 支持**: 代码质询防止授权码拦截攻击
- **JWT ID Token**: 标准的身份令牌生成和验证
- **多客户端支持**: 支持 Web、移动、SPA 等不同类型客户端
- **会话管理**: 完整的 SSO 会话生命周期管理
- **单点登出**: 支持全局和单应用登出
- **Discovery 端点**: 标准的 OIDC 发现和配置端点

### 最新更新 (OIDC SSO 系统完成版本) 🎉
- 🔐 **OIDC 单点登录完成**: 完整的企业级 SSO 解决方案（第五阶段已完成）
  - ✅ **OIDC 核心协议**: 完整的 OpenID Connect 1.0 实现
  - ✅ **标准端点**: Discovery、授权、令牌、用户信息、登出端点
  - ✅ **授权码流程**: 支持 PKCE 的安全授权码流程
  - ✅ **令牌管理**: 访问令牌、刷新令牌、ID 令牌完整生命周期
  - ✅ **客户端管理**: 多类型客户端注册、配置、密钥管理
  - ✅ **SSO 会话**: 跨应用会话同步、单点登出、会话统计
  - ✅ **安全特性**: PKCE、作用域控制、客户端认证、签名验证
- 📊 **监控审计系统完成**: 全面的安全监控和审计体系（第四阶段已完成）
  - ✅ **安全仪表板**: 实时安全指标概览和趋势分析
  - ✅ **审计日志分析**: 用户活动分类统计和行为分析
  - ✅ **安全事件监控**: 失败登录、权限拒绝、可疑活动检测
  - ✅ **系统健康监控**: 数据库状态、内存使用、连接池监控
  - ✅ **安全报告生成**: 自动生成详细的安全分析报告
  - ✅ **威胁检测**: 基于行为模式的异常活动识别
  - ✅ **性能指标**: 认证成功率、锁定统计、速率限制违规
  - ✅ **风险评估**: 自动风险级别计算和安全建议
- 👤 **用户生命周期管理完成**: 完整的用户管理体系（第三阶段已完成）
  - ✅ **用户档案系统**: 完整个人信息管理、联系方式、头像支持
  - ✅ **账户状态管理**: 五种状态控制（Active、Inactive、Suspended、PendingDeletion、Deleted）
  - ✅ **用户偏好设置**: 主题、语言、通知、安全偏好等个性化配置
  - ✅ **活动审计系统**: 详细操作日志、分类管理、时间范围查询
  - ✅ **管理员功能**: 用户列表、搜索、状态变更、批量管理
  - ✅ **登录追踪**: 最后登录时间和IP地址记录
  - ✅ **权限集成**: 与RBAC系统完全集成的权限控制
- 🔐 **权限系统完成**: 完整的RBAC（基于角色的访问控制）系统（第二阶段已完成）
  - ✅ **角色管理**: 创建、编辑、查询角色，支持系统角色和自定义角色
  - ✅ **权限管理**: 基于资源和操作的细粒度权限控制
  - ✅ **用户角色分配**: 灵活的用户角色分配和移除机制
  - ✅ **权限检查中间件**: 便捷的权限验证宏和中间件
  - ✅ **系统初始化**: 自动创建系统角色和权限
  - ✅ **权限保护**: 所有RBAC接口都有相应的权限保护
- 🛡️ **安全防护层**: 全面的安全防护体系（第一阶段已完成）
  - ✅ **速率限制**: 智能API请求频率控制，防止暴力破解
  - ✅ **多因素认证**: 完整TOTP/Google Authenticator支持
  - ✅ **账户锁定**: 自动锁定机制，多维度安全保护
  - ✅ **设备安全**: IP和用户双重锁定策略
  - ✅ **自动管理**: 定期清理和智能解锁
- 🔒 **安全修复**: 移除JWT密钥硬编码，强制使用环境变量
- 🔒 **安全修复**: 移除敏感信息日志泄露（邮箱、令牌等）
- 🔒 **数据库安全**: 添加连接超时和错误处理改进
- ✨ **新功能**: 完整的密码重置流程（请求重置、验证令牌、重置密码）
- ✨ **新功能**: 真正的会话管理系统（登出、会话列表、批量登出）
- 🔧 **修复**: 邮箱验证逻辑优化（注册后强制验证才能登录）
- 🔧 **修复**: OAuth 用户记录处理改进
- 📊 **数据库**: 新增 password_reset_token、session、user_mfa、account_lockout、role、permission、user_role、role_permission、user_profile、user_preferences、user_activity、oidc_client、oidc_authorization_code、oidc_access_token、oidc_refresh_token、sso_session 表
- 📊 **监控审计**: 完整的审计API端点集，支持安全仪表板、指标分析、系统健康监控和安全报告生成

## 技术栈

- **后端框架**: [Axum](https://github.com/tokio-rs/axum)
- **数据库**: [SurrealDB](https://surrealdb.com/)
- **认证**: [jsonwebtoken](https://github.com/Keats/jsonwebtoken)
- **密码加密**: [Argon2](https://github.com/RustCrypto/password-hashes/tree/master/argon2)
- **邮件服务**: [lettre](https://github.com/lettre/lettre)
- **OAuth**: [oauth2](https://github.com/ramosbugs/oauth2-rs)
- **多因素认证**: [totp-rs](https://github.com/constantoine/totp-rs) + [qrcode](https://github.com/kennytm/qrcode-rust)
- **速率限制**: 自研高性能内存缓存系统
- **权限系统**: 自研RBAC权限控制框架
- **安全组件**: Tower middleware + 自定义安全层 + 权限中间件

## 快速开始

### 环境要求
- Rust 1.70.0 或更高版本
- SurrealDB
- SMTP 服务器（用于发送邮件）

### 配置

1. 克隆项目
```bash
git clone https://github.com/yourusername/rust-auth.git
cd rust-auth
```

2. 配置环境变量
创建 `.env` 文件并添加以下配置：

```env
# 数据库配置
DATABASE_URL=http://localhost:8000
DATABASE_USER=root
DATABASE_PASS=root
DATABASE_CONNECTION_TIMEOUT=30
DATABASE_MAX_CONNECTIONS=10

# JWT配置 (必需)
JWT_SECRET=your-super-secure-jwt-secret-key-here
JWT_EXPIRATION=86400

# Google OAuth配置
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth配置
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# OAuth回调URL
OAUTH_REDIRECT_URL=http://localhost:8080/api/auth/callback

# SMTP配置
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password
SMTP_FROM=noreply@example.com

# 应用配置
APP_URL=http://localhost:8080
EMAIL_VERIFICATION_ENABLED=false

# 代理配置（可选）
PROXY_ENABLED=false
PROXY_URL=http://your-proxy:port
```

3. 构建和运行
```bash
cargo build
cargo run
HTTP_PROXY=http://192.168.101.121:7890 HTTPS_PROXY=http://192.168.101.121:7890 cargo run
```

## 数据库结构

### 用户表 (user)
```sql
DEFINE TABLE user SCHEMALESS;
```

字段:
- id: Thing - 用户唯一标识符
- email: string - 用户邮箱
- password: string - 加密后的密码
- email_verified: bool - 邮箱验证状态
- account_status: string - 账户状态（Active、Inactive、Suspended、PendingDeletion、Deleted）
- last_login_at: number - 最后登录时间戳
- last_login_ip: string - 最后登录IP地址
- created_at: datetime - 创建时间
- updated_at: datetime - 更新时间

### 身份提供商表 (identity_provider)
```sql
DEFINE TABLE identity_provider SCHEMAFULL;
```

字段:
- id: Thing - 记录唯一标识符
- provider: string - 提供商名称 (google/github)
- provider_user_id: string - 提供商用户ID
- user_id: Thing - 关联的用户ID
- created_at: number - 创建时间戳
- updated_at: number - 更新时间戳

### 会话表 (session)
```sql
DEFINE TABLE session SCHEMAFULL;
```

字段:
- id: Thing - 会话唯一标识符
- user_id: Thing - 关联的用户ID
- token: string - JWT令牌
- expires_at: number - 过期时间戳
- created_at: number - 创建时间戳
- user_agent: string - 用户代理
- ip_address: string - IP地址

### 密码重置令牌表 (password_reset_token)
```sql
DEFINE TABLE password_reset_token SCHEMAFULL;
```

字段:
- id: Thing - 令牌唯一标识符
- email: string - 用户邮箱
- token: string - 重置令牌
- expires_at: datetime - 过期时间
- used: bool - 是否已使用
- created_at: datetime - 创建时间

### 多因素认证表 (user_mfa)
```sql
DEFINE TABLE user_mfa SCHEMAFULL;
```

字段:
- id: Thing - MFA记录唯一标识符
- user_id: string - 用户ID
- status: string - MFA状态 (Disabled/Pending/Enabled)
- method: string - MFA方法 (Totp/Sms/Email)
- totp_secret: string - TOTP密钥（加密存储）
- backup_codes: array - 备用恢复代码列表
- created_at: datetime - 创建时间
- updated_at: datetime - 更新时间
- last_used_at: datetime - 最后使用时间

### 账户锁定表 (account_lockout)
```sql
DEFINE TABLE account_lockout SCHEMAFULL;
```

字段:
- id: Thing - 锁定记录唯一标识符
- identifier: string - 标识符（用户ID或IP地址）
- lockout_type: string - 锁定类型 (User/IpAddress)
- failed_attempts: number - 失败尝试次数
- status: string - 锁定状态 (Normal/Locked/TemporaryLocked)
- locked_at: datetime - 锁定开始时间
- locked_until: datetime - 锁定结束时间
- last_attempt_at: datetime - 最后尝试时间
- created_at: datetime - 创建时间
- updated_at: datetime - 更新时间

### 角色表 (role)
```sql
DEFINE TABLE role SCHEMAFULL;
```

字段:
- id: Thing - 角色唯一标识符
- name: string - 角色名称（唯一）
- display_name: string - 角色显示名称
- description: string - 角色描述
- is_system: bool - 是否为系统角色（系统角色不可删除）
- created_at: number - 创建时间戳
- updated_at: number - 更新时间戳

### 权限表 (permission)
```sql
DEFINE TABLE permission SCHEMAFULL;
```

字段:
- id: Thing - 权限唯一标识符
- name: string - 权限名称（唯一）
- display_name: string - 权限显示名称
- description: string - 权限描述
- resource: string - 资源类型（如 users, roles, permissions）
- action: string - 操作类型（如 read, write, delete）
- is_system: bool - 是否为系统权限
- created_at: number - 创建时间戳
- updated_at: number - 更新时间戳

### 用户角色关联表 (user_role)
```sql
DEFINE TABLE user_role SCHEMAFULL;
```

字段:
- id: Thing - 关联唯一标识符
- user_id: record<user> - 用户ID
- role_id: record<role> - 角色ID
- assigned_at: number - 分配时间戳
- assigned_by: record<user> - 分配者用户ID

### 角色权限关联表 (role_permission)
```sql
DEFINE TABLE role_permission SCHEMAFULL;
```

字段:
- id: Thing - 关联唯一标识符
- role_id: record<role> - 角色ID
- permission_id: record<permission> - 权限ID
- granted_at: number - 授权时间戳
- granted_by: record<user> - 授权者用户ID

### 用户档案表 (user_profile)
```sql
DEFINE TABLE user_profile SCHEMAFULL;
```

字段:
- id: Thing - 档案唯一标识符
- user_id: record<user> - 关联的用户ID
- first_name: string - 名字
- last_name: string - 姓氏
- display_name: string - 显示名称
- avatar_url: string - 头像URL
- phone: string - 电话号码
- date_of_birth: datetime - 出生日期
- timezone: string - 时区
- locale: string - 地区语言
- bio: string - 个人简介
- website: string - 个人网站
- location: string - 位置信息
- created_at: number - 创建时间戳
- updated_at: number - 更新时间戳

### 用户偏好表 (user_preferences)
```sql
DEFINE TABLE user_preferences SCHEMAFULL;
```

字段:
- id: Thing - 偏好唯一标识符
- user_id: record<user> - 关联的用户ID
- theme: string - 主题（light、dark、auto）
- language: string - 语言代码
- email_notifications: bool - 邮件通知开关
- sms_notifications: bool - 短信通知开关
- marketing_emails: bool - 营销邮件开关
- security_emails: bool - 安全邮件开关
- newsletter: bool - 新闻通讯开关
- two_factor_required: bool - 是否强制双因素认证
- session_timeout: number - 会话超时时间（秒）
- timezone: string - 用户时区
- date_format: string - 日期格式
- time_format: string - 时间格式
- created_at: number - 创建时间戳
- updated_at: number - 更新时间戳

### 用户活动日志表 (user_activity)
```sql
DEFINE TABLE user_activity SCHEMAFULL;
```

字段:
- id: Thing - 活动唯一标识符
- user_id: record<user> - 关联的用户ID
- action: string - 操作名称
- category: string - 活动分类（Authentication、Profile、Security、Permissions、Data、System）
- ip_address: string - IP地址
- user_agent: string - 用户代理
- details: object - 详细信息JSON
- status: string - 状态（Success、Failed、Warning、Info）
- timestamp: number - 时间戳

### OIDC 客户端表 (oidc_client)
```sql
DEFINE TABLE oidc_client SCHEMAFULL;
```

字段:
- id: Thing - 客户端唯一标识符
- client_id: string - 客户端ID（唯一）
- client_secret_hash: string - 客户端密钥哈希
- client_name: string - 客户端名称
- client_type: string - 客户端类型（public/confidential）
- redirect_uris: array - 重定向URI列表
- post_logout_redirect_uris: array - 登出后重定向URI列表
- allowed_scopes: array - 允许的作用域列表
- allowed_grant_types: array - 允许的授权类型
- allowed_response_types: array - 允许的响应类型
- require_pkce: bool - 是否要求PKCE
- access_token_lifetime: number - 访问令牌生命周期（秒）
- refresh_token_lifetime: number - 刷新令牌生命周期（秒）
- id_token_lifetime: number - ID令牌生命周期（秒）
- is_active: bool - 是否活跃
- created_by: record<user> - 创建者
- created_at: number - 创建时间戳
- updated_at: number - 更新时间戳

### OIDC 授权码表 (oidc_authorization_code)
```sql
DEFINE TABLE oidc_authorization_code SCHEMAFULL;
```

字段:
- id: Thing - 授权码唯一标识符
- code: string - 授权码（唯一）
- client_id: string - 客户端ID
- user_id: record<user> - 用户ID
- redirect_uri: string - 重定向URI
- scope: string - 作用域
- state: string - 状态参数
- nonce: string - 随机数
- code_challenge: string - PKCE代码质询
- code_challenge_method: string - PKCE质询方法
- used: bool - 是否已使用
- expires_at: number - 过期时间戳
- created_at: number - 创建时间戳

### OIDC 访问令牌表 (oidc_access_token)
```sql
DEFINE TABLE oidc_access_token SCHEMAFULL;
```

字段:
- id: Thing - 令牌唯一标识符
- token: string - 访问令牌（唯一）
- token_type: string - 令牌类型（Bearer）
- client_id: string - 客户端ID
- user_id: record<user> - 用户ID
- scope: string - 作用域
- expires_at: number - 过期时间戳
- created_at: number - 创建时间戳

### OIDC 刷新令牌表 (oidc_refresh_token)
```sql
DEFINE TABLE oidc_refresh_token SCHEMAFULL;
```

字段:
- id: Thing - 令牌唯一标识符
- token: string - 刷新令牌（唯一）
- client_id: string - 客户端ID
- user_id: record<user> - 用户ID
- access_token: string - 关联的访问令牌
- scope: string - 作用域
- used: bool - 是否已使用
- expires_at: number - 过期时间戳
- created_at: number - 创建时间戳

### SSO 会话表 (sso_session)
```sql
DEFINE TABLE sso_session SCHEMAFULL;
```

字段:
- id: Thing - 会话唯一标识符
- session_id: string - 会话ID（唯一）
- user_id: record<user> - 用户ID
- client_sessions: array - 客户端会话列表
- created_at: number - 创建时间戳
- last_accessed_at: number - 最后访问时间戳
- expires_at: number - 过期时间戳
- ip_address: string - IP地址
- user_agent: string - 用户代理

## API 端点

### 用户认证
- `POST /api/auth/register` - 用户注册（需验证邮箱）
- `POST /api/auth/login` - 用户登录
- `GET /api/auth/verify-email/:token` - 验证邮箱（返回JWT令牌）
- `GET /api/auth/me` - 获取当前用户信息
- `POST /api/auth/initialize-password` - 初始化密码（OAuth用户）

### 密码管理
- `POST /api/auth/request-password-reset` - 请求密码重置
- `POST /api/auth/reset-password` - 重置密码

### 会话管理
- `POST /api/auth/logout` - 登出当前会话
- `POST /api/auth/logout-all` - 登出所有会话
- `GET /api/auth/sessions` - 获取用户所有会话

### OAuth认证
- `GET /api/auth/login/google` - Google登录
- `GET /api/auth/callback/google` - Google回调处理
- `GET /api/auth/login/github` - GitHub登录
- `GET /api/auth/callback/github` - GitHub回调处理

### 多因素认证 (MFA) 🔐
- `POST /api/auth/mfa/setup-totp` - 初始化TOTP设置（获取QR码）
- `POST /api/auth/mfa/enable-totp` - 启用TOTP（验证初始代码）
- `POST /api/auth/mfa/verify-totp` - 验证TOTP代码
- `POST /api/auth/mfa/use-backup-code` - 使用备用恢复代码
- `POST /api/auth/mfa/disable` - 禁用MFA
- `GET /api/auth/mfa/status` - 获取MFA状态

### 安全管理 🛡️
- `GET /api/auth/security/lockout-status` - 查看账户锁定状态
- `POST /api/auth/security/unlock-account` - 管理员解锁账户
- `GET /api/auth/security/rate-limit-status` - 查看速率限制状态

### 权限系统 (RBAC) 🔐
#### 角色管理
- `GET /api/rbac/roles` - 获取角色列表（支持分页）
- `POST /api/rbac/roles` - 创建新角色
- `GET /api/rbac/roles/:role_name` - 获取指定角色详情
- `POST /api/rbac/roles/:role_name` - 更新角色信息
- `GET /api/rbac/roles/:role_name/permissions` - 获取角色权限列表

#### 权限管理
- `GET /api/rbac/permissions` - 获取权限列表（支持分页）
- `POST /api/rbac/permissions` - 创建新权限
- `GET /api/rbac/permissions/:permission_name` - 获取指定权限详情

#### 角色权限分配
- `POST /api/rbac/roles/:role_name/permissions/assign` - 为角色分配权限
- `POST /api/rbac/roles/:role_name/permissions/remove` - 移除角色权限

#### 用户角色管理
- `GET /api/rbac/users/:user_id/roles` - 获取用户角色列表
- `POST /api/rbac/users/:user_id/roles/assign` - 为用户分配角色
- `POST /api/rbac/users/:user_id/roles/remove` - 移除用户角色
- `GET /api/rbac/users/:user_id/permissions` - 获取用户所有权限

#### 权限检查
- `GET /api/rbac/check/permission/:permission_name` - 检查当前用户是否具有指定权限
- `GET /api/rbac/check/role/:role_name` - 检查当前用户是否具有指定角色

### 监控审计系统 📊
#### 安全仪表板（需要audit.read权限）
- `GET /api/audit/dashboard` - 获取安全仪表板概览（支持days参数）
- `GET /api/audit/security-metrics` - 获取安全指标详情（支持hours参数）
- `GET /api/audit/activity-summary` - 获取活动统计汇总（支持days参数）
- `GET /api/audit/system-health` - 获取系统健康状态（需要security.read权限）
- `GET /api/audit/security-report` - 生成安全分析报告（支持days参数）

### 用户生命周期管理 👤
#### 用户档案管理
- `POST /api/users/profile` - 创建用户档案
- `GET /api/users/profile` - 获取当前用户档案
- `PUT /api/users/profile` - 更新当前用户档案

#### 用户偏好设置
- `POST /api/users/preferences` - 创建用户偏好设置
- `GET /api/users/preferences` - 获取当前用户偏好设置
- `PUT /api/users/preferences` - 更新当前用户偏好设置

#### 用户活动日志
- `GET /api/users/activity-log` - 获取当前用户活动日志（支持分页和过滤）

#### 管理员功能（需要相应权限）
- `GET /api/users/users` - 获取用户列表（需要users.read权限）
- `PUT /api/users/users/:user_id/status` - 更新用户账户状态（需要users.write权限）
- `GET /api/users/users/:user_id/profile` - 查看指定用户档案（需要users.read权限）
- `GET /api/users/users/:user_id/preferences` - 查看指定用户偏好（需要users.read权限）
- `GET /api/users/users/:user_id/activity-log` - 查看指定用户活动日志（需要audit.read权限）

### OIDC 单点登录 🔐

#### OIDC 核心端点
- `GET /.well-known/openid-configuration` - OIDC Discovery 端点
- `GET /api/oidc/jwks` - JSON Web Key Set 端点
- `GET /api/oidc/authorize` - 授权端点（支持授权码流程）
- `POST /api/oidc/token` - 令牌端点（授权码交换、刷新令牌）
- `GET /api/oidc/userinfo` - 用户信息端点
- `GET /api/oidc/logout` - 单点登出端点

#### OIDC 客户端管理
- `POST /api/oidc/clients` - 创建OIDC客户端
- `GET /api/oidc/clients` - 获取客户端列表（支持分页）
- `GET /api/oidc/clients/:client_id` - 获取客户端详情
- `PUT /api/oidc/clients/:client_id` - 更新客户端配置
- `DELETE /api/oidc/clients/:client_id` - 禁用客户端
- `POST /api/oidc/clients/:client_id/regenerate-secret` - 重新生成客户端密钥

#### SSO 会话管理
- `POST /api/sso/sessions` - 创建SSO会话
- `GET /api/sso/sessions/:session_id` - 获取SSO会话信息
- `DELETE /api/sso/sessions/:session_id` - 终止SSO会话
- `POST /api/sso/sessions/:session_id/clients/:client_id` - 添加客户端会话
- `DELETE /api/sso/sessions/:session_id/clients/:client_id` - 移除客户端会话（单点登出）
- `POST /api/sso/sessions/:session_id/extend` - 延长会话时间
- `GET /api/sso/users/:user_id/sessions` - 获取用户所有SSO会话
- `DELETE /api/sso/users/:user_id/sessions` - 终止用户所有SSO会话
- `GET /api/sso/users/:user_id/sessions/stats` - 获取用户会话统计
- `GET /api/sso/sessions/stats` - 获取全局会话统计
- `POST /api/sso/sessions/cleanup` - 清理过期会话

## API 示例

所有接口在出错时会返回统一的错误格式：
```json
{
    "error": "错误信息描述"
}
```

### 注册新用户
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# 成功响应 (200 OK)
"Registration successful. Please check your email to verify your account."

# 可能的错误响应
# 409 Conflict - 邮箱已存在
{
    "error": "Email already exists"
}
# 400 Bad Request - 无效的邮箱格式
{
    "error": "Invalid email format"
}
```

### 用户登录
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# 成功响应 (200 OK)
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": "user_2x8j9z",
        "email": "user@example.com",
        "email_verified": true,
        "created_at": "2025-04-01T02:45:29Z"
    }
}

# 可能的错误响应
# 401 Unauthorized - 凭据无效
{
    "error": "Invalid credentials"
}
# 403 Forbidden - 邮箱未验证
{
    "error": "Email not verified"
}
```

### 获取用户信息
```bash
# 请求
curl http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
    "id": "user_2x8j9z",
    "email": "user@example.com",
    "email_verified": true,
    "created_at": "2025-04-01T02:45:29Z",
    "oauth_providers": [
        {
            "provider": "google",
            "email": "user@gmail.com"
        }
    ]
}

# 可能的错误响应
# 401 Unauthorized - 无效或过期的令牌
{
    "error": "Invalid token"
}
```

### 验证邮箱
```bash
# 请求
curl http://localhost:8080/api/auth/verify-email/verification-token-here

# 成功响应 (200 OK) - 验证成功并返回JWT令牌
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": "user_2x8j9z",
        "email": "user@example.com",
        "email_verified": true,
        "created_at": "2025-04-01T02:45:29Z"
    }
}

# 可能的错误响应
# 400 Bad Request - 无效的验证令牌
{
    "error": "Invalid token"
}
```

### 请求密码重置
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/request-password-reset \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'

# 成功响应 (200 OK)
"Password reset email sent if account exists"
```

### 重置密码
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-from-email",
    "new_password": "newpassword123"
  }'

# 成功响应 (200 OK)
"Password reset successfully"

# 可能的错误响应
# 400 Bad Request - 无效或过期的重置令牌
{
    "error": "Invalid token"
}
```

### 登出当前会话
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
"Logged out successfully"
```

### 登出所有会话
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/logout-all \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
"All sessions logged out successfully"
```

### 获取用户会话列表
```bash
# 请求
curl http://localhost:8080/api/auth/sessions \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
[
    {
        "id": "session_abc123",
        "created_at": "2025-04-01T02:45:29Z",
        "user_agent": "Mozilla/5.0...",
        "ip_address": "192.168.1.100",
        "is_current": true
    },
    {
        "id": "session_def456",
        "created_at": "2025-03-31T18:30:15Z",
        "user_agent": "Chrome/91.0...",
        "ip_address": "192.168.1.101",
        "is_current": false
    }
]
```

### OAuth 登录回调
```bash
# Google/GitHub OAuth 回调响应
# 成功时重定向到：
/login/success?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# 失败时重定向到：
/login/error?error=授权失败的原因
```

### OAuth 用户信息示例
```json
# OAuth 登录成功后的用户信息
{
    "id": "user_2x8j9z",
    "email": "user@gmail.com",
    "email_verified": true,
    "created_at": "2025-04-01T02:45:29Z",
    "oauth_providers": [
        {
            "provider": "google",
            "email": "user@gmail.com",
            "name": "John Doe",
            "picture": "https://lh3.googleusercontent.com/..."
        }
    ]
}
```

所有 API 都支持跨域请求（CORS），并使用标准的 HTTP 状态码：
- 200: 成功
- 400: 请求参数错误
- 401: 未授权
- 403: 禁止访问
- 404: 资源不存在
- 409: 资源冲突
- 500: 服务器错误

## 前端集成

### OAuth登录示例
```javascript
// Google登录
function loginWithGoogle() {
  window.location.href = '/api/auth/login/google';
}

// GitHub登录
function loginWithGithub() {
  window.location.href = '/api/auth/login/github';
}

// 处理OAuth回调
if (window.location.pathname === '/login/success') {
  const token = new URLSearchParams(window.location.search).get('token');
  if (token) {
    localStorage.setItem('auth_token', token);
    window.location.href = '/';
  }
}
```

### MFA (多因素认证) 示例

#### 设置TOTP
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/mfa/setup-totp \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCI+Li4uPC9zdmc+",
  "backup_codes": [
    "ABCD1234", "EFGH5678", "IJKL9012", "MNOP3456",
    "QRST7890", "UVWX1234", "YZAB5678", "CDEF9012"
  ]
}
```

#### 启用TOTP
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/mfa/enable-totp \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "totp_code": "123456"
  }'

# 成功响应 (200 OK)
{
  "success": true,
  "message": "TOTP enabled successfully"
}
```

#### 验证TOTP
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/mfa/verify-totp \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "totp_code": "654321"
  }'

# 成功响应 (200 OK)
{
  "verified": true,
  "message": "TOTP verification successful"
}
```

### 权限系统 (RBAC) 示例

#### 创建角色
```bash
# 请求
curl -X POST http://localhost:8080/api/rbac/roles \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "editor",
    "display_name": "编辑员",
    "description": "可以编辑内容的用户角色"
  }'

# 成功响应 (200 OK)
{
  "success": true,
  "data": {
    "id": "role_xyz789",
    "name": "editor",
    "display_name": "编辑员",
    "description": "可以编辑内容的用户角色",
    "is_system": false,
    "created_at": "2025-04-01T10:30:00Z",
    "updated_at": "2025-04-01T10:30:00Z",
    "permissions": []
  },
  "message": "Role created successfully"
}
```

#### 获取角色列表
```bash
# 请求
curl http://localhost:8080/api/rbac/roles?page=1&limit=10 \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "success": true,
  "data": [
    {
      "id": "role_admin",
      "name": "admin",
      "display_name": "系统管理员",
      "description": "拥有所有权限的系统管理员",
      "is_system": true,
      "created_at": "2025-04-01T08:00:00Z",
      "updated_at": "2025-04-01T08:00:00Z",
      "permissions": ["users.read", "users.write", "roles.read", "roles.write"]
    }
  ],
  "message": "Roles retrieved successfully"
}
```

#### 为用户分配角色
```bash
# 请求
curl -X POST http://localhost:8080/api/rbac/users/user123/roles/assign \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user123",
    "role_name": "editor"
  }'

# 成功响应 (200 OK)
{
  "success": true,
  "data": null,
  "message": "Role assigned to user successfully"
}
```

#### 检查用户权限
```bash
# 请求
curl http://localhost:8080/api/rbac/check/permission/users.read \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "success": true,
  "data": {
    "has_permission": true,
    "user_id": "user123",
    "permission": "users.read"
  },
  "message": "Permission checked successfully"
}
```

#### 获取用户角色和权限
```bash
# 请求
curl http://localhost:8080/api/rbac/users/user123/roles \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "success": true,
  "data": {
    "user_id": "user123",
    "roles": [
      {
        "id": "role_editor",
        "name": "editor",
        "display_name": "编辑员",
        "description": "可以编辑内容的用户角色",
        "permissions": ["users.read", "content.write"],
        "assigned_at": "2025-04-01T11:00:00Z"
      }
    ]
  },
  "message": "User roles retrieved successfully"
}
```

### 监控审计系统示例

#### 获取安全仪表板
```bash
# 请求
curl "http://localhost:8080/api/audit/dashboard?days=7" \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "period": "Last 7 days",
  "total_users": 150,
  "active_sessions": 25,
  "failed_logins": 12,
  "locked_accounts": 2,
  "security_events": 8,
  "top_activities": [
    {
      "action": "login_success",
      "count": 340,
      "percentage": 65.4
    },
    {
      "action": "profile_updated",
      "count": 89,
      "percentage": 17.1
    }
  ],
  "login_trends": [
    {
      "timestamp": "2025-04-07T00:00:00Z",
      "value": 45
    }
  ],
  "security_trends": [
    {
      "timestamp": "2025-04-07T00:00:00Z",
      "value": 3
    }
  ]
}
```

#### 获取安全指标
```bash
# 请求
curl "http://localhost:8080/api/audit/security-metrics?hours=24" \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "period": "Last 24 hours",
  "authentication_stats": {
    "successful_logins": 127,
    "failed_logins": 15,
    "oauth_logins": 23,
    "password_resets": 3,
    "success_rate": 89.4
  },
  "lockout_stats": {
    "user_lockouts": 2,
    "ip_lockouts": 1,
    "active_lockouts": 1,
    "average_lockout_duration_minutes": 15.0
  },
  "rate_limit_violations": 5,
  "permission_denials": 8,
  "failed_login_by_ip": [
    {
      "ip_address": "192.168.1.100",
      "failed_attempts": 7,
      "is_locked": false,
      "last_attempt": "2025-04-07T14:30:00Z"
    }
  ],
  "suspicious_activities": [
    {
      "user_id": "user_123",
      "ip_address": "10.0.0.50",
      "activity_type": "login_failed",
      "count": 8,
      "risk_score": 6,
      "first_seen": "2025-04-07T12:00:00Z",
      "last_seen": "2025-04-07T14:30:00Z"
    }
  ]
}
```

#### 获取系统健康状态
```bash
# 请求
curl http://localhost:8080/api/audit/system-health \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "timestamp": "2025-04-07T15:00:00Z",
  "database_status": {
    "connected": true,
    "response_time_ms": 12,
    "connection_pool_used": 3,
    "connection_pool_size": 10
  },
  "active_sessions_count": 25,
  "pending_lockouts": 1,
  "memory_usage": {
    "used_mb": 128.0,
    "available_mb": 512.0,
    "usage_percentage": 25.0
  },
  "uptime_seconds": 3600
}
```

#### 生成安全报告
```bash
# 请求
curl "http://localhost:8080/api/audit/security-report?days=30" \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "generated_at": "2025-04-07T15:00:00Z",
  "period": "Last 30 days",
  "executive_summary": {
    "total_users": 150,
    "active_users": 89,
    "security_incidents": 12,
    "success_rate": 94.2,
    "risk_level": "Low"
  },
  "authentication_analysis": {
    "login_patterns": [
      {
        "pattern_type": "Regular Login",
        "count": 100,
        "trend": "Stable"
      }
    ],
    "failure_analysis": [
      {
        "failure_reason": "Invalid Password",
        "count": 25,
        "percentage": 75.0
      }
    ],
    "geographic_distribution": [
      {
        "country": "US",
        "region": "California",
        "count": 80
      }
    ]
  },
  "security_incidents": [
    {
      "id": "incident_001",
      "incident_type": "Multiple Failed Logins",
      "severity": "Medium",
      "affected_user": "user_123",
      "ip_address": "192.168.1.100",
      "description": "Multiple failed login attempts from same IP",
      "timestamp": "2025-04-07T13:00:00Z",
      "resolved": false
    }
  ],
  "user_behavior_analysis": {
    "login_frequency_distribution": [
      {
        "frequency_range": "Daily",
        "user_count": 50,
        "percentage": 60.0
      }
    ],
    "peak_activity_hours": [9, 10, 11, 14, 15, 16],
    "user_retention_metrics": {
      "daily_retention": 85.0,
      "weekly_retention": 70.0,
      "monthly_retention": 60.0
    }
  },
  "recommendations": [
    {
      "priority": "Low",
      "category": "General",
      "title": "Security Status Normal",
      "description": "No critical security issues detected in the analysis period. Continue monitoring and maintain current security practices.",
      "estimated_impact": "Low"
    }
  ]
}
```

### 用户生命周期管理示例

#### 创建用户档案
```bash
# 请求
curl -X POST http://localhost:8080/api/users/profile \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "first_name": "张",
    "last_name": "三",
    "display_name": "张三",
    "phone": "+86-13812345678",
    "timezone": "Asia/Shanghai",
    "locale": "zh-CN",
    "bio": "这是我的个人简介",
    "website": "https://zhangsan.com",
    "location": "北京, 中国"
  }'

# 成功响应 (200 OK)
{
  "success": true,
  "data": {
    "id": "profile_abc123",
    "user_id": "user_xyz789",
    "first_name": "张",
    "last_name": "三",
    "display_name": "张三",
    "avatar_url": null,
    "phone": "+86-13812345678",
    "timezone": "Asia/Shanghai",
    "locale": "zh-CN",
    "bio": "这是我的个人简介",
    "website": "https://zhangsan.com",
    "location": "北京, 中国",
    "created_at": "2025-04-01T12:00:00Z",
    "updated_at": "2025-04-01T12:00:00Z"
  },
  "message": "User profile created successfully"
}
```

#### 创建用户偏好设置
```bash
# 请求
curl -X POST http://localhost:8080/api/users/preferences \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "theme": "dark",
    "language": "zh-CN",
    "email_notifications": true,
    "sms_notifications": false,
    "marketing_emails": false,
    "security_emails": true,
    "newsletter": false,
    "two_factor_required": true,
    "session_timeout": 7200,
    "timezone": "Asia/Shanghai",
    "date_format": "YYYY-MM-DD",
    "time_format": "24h"
  }'

# 成功响应 (200 OK)
{
  "success": true,
  "data": {
    "id": "prefs_def456",
    "user_id": "user_xyz789",
    "theme": "dark",
    "language": "zh-CN",
    "email_notifications": true,
    "sms_notifications": false,
    "marketing_emails": false,
    "security_emails": true,
    "newsletter": false,
    "two_factor_required": true,
    "session_timeout": 7200,
    "timezone": "Asia/Shanghai",
    "date_format": "YYYY-MM-DD",
    "time_format": "24h",
    "created_at": "2025-04-01T12:30:00Z",
    "updated_at": "2025-04-01T12:30:00Z"
  },
  "message": "User preferences created successfully"
}
```

#### 更新用户账户状态（管理员功能）
```bash
# 请求
curl -X PUT http://localhost:8080/api/users/users/user123/status \
  -H "Authorization: Bearer admin-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "Suspended",
    "reason": "违反用户协议"
  }'

# 成功响应 (200 OK)
{
  "success": true,
  "data": {
    "user_id": "user123",
    "status": "Suspended",
    "updated_at": "2025-04-01T13:00:00Z",
    "updated_by": "admin@example.com",
    "reason": "违反用户协议"
  },
  "message": "Account status updated successfully"
}
```

#### 获取用户活动日志
```bash
# 请求
curl "http://localhost:8080/api/users/activity-log?page=1&limit=10&category=Profile" \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "success": true,
  "data": {
    "activities": [
      {
        "id": "activity_ghi789",
        "user_id": "user_xyz789",
        "action": "profile_updated",
        "category": "Profile",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "details": {
          "action": "profile_updated",
          "fields": ["display_name", "bio"]
        },
        "status": "Success",
        "timestamp": "2025-04-01T12:15:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "limit": 10,
    "total_pages": 1
  },
  "message": "User activity log retrieved successfully"
}
```

#### 获取用户列表（管理员功能）
```bash
# 请求
curl "http://localhost:8080/api/users/users?page=1&limit=10&status=Active&search=zhang" \
  -H "Authorization: Bearer admin-jwt-token"

# 成功响应 (200 OK)
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "user_xyz789",
        "email": "zhangsan@example.com",
        "is_email_verified": true,
        "account_status": "Active",
        "last_login_at": "2025-04-01T12:00:00Z",
        "created_at": "2025-03-01T10:00:00Z",
        "has_password": true
      }
    ],
    "total": 1,
    "page": 1,
    "limit": 10,
    "total_pages": 1
  },
  "message": "Users retrieved successfully"
}
```

### OIDC 单点登录示例

#### OIDC Discovery 配置
```bash
# 请求
curl http://localhost:8080/.well-known/openid-configuration

# 成功响应 (200 OK)
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/api/oidc/authorize",
  "token_endpoint": "http://localhost:8080/api/oidc/token",
  "userinfo_endpoint": "http://localhost:8080/api/oidc/userinfo",
  "jwks_uri": "http://localhost:8080/api/oidc/jwks",
  "end_session_endpoint": "http://localhost:8080/api/oidc/logout",
  "response_types_supported": ["code", "id_token"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["HS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "code_challenge_methods_supported": ["S256", "plain"]
}
```

#### 创建 OIDC 客户端
```bash
# 请求
curl -X POST http://localhost:8080/api/oidc/clients \
  -H "Authorization: Bearer admin-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Web App",
    "client_type": "confidential",
    "redirect_uris": ["https://myapp.com/callback"],
    "post_logout_redirect_uris": ["https://myapp.com/logout"],
    "allowed_scopes": ["openid", "profile", "email"],
    "require_pkce": true
  }'

# 成功响应 (200 OK)
{
  "client_id": "client_1634567890abc123def",
  "client_secret": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6A7B8C9D0E1F2G3",
  "client_name": "My Web App",
  "client_type": "confidential",
  "redirect_uris": ["https://myapp.com/callback"],
  "post_logout_redirect_uris": ["https://myapp.com/logout"],
  "allowed_scopes": ["openid", "profile", "email"],
  "allowed_grant_types": ["authorization_code", "refresh_token"],
  "allowed_response_types": ["code"],
  "require_pkce": true,
  "access_token_lifetime": 3600,
  "refresh_token_lifetime": 86400,
  "id_token_lifetime": 3600,
  "is_active": true,
  "created_at": "2025-04-07T15:30:00Z",
  "updated_at": "2025-04-07T15:30:00Z"
}
```

#### OIDC 授权流程
```bash
# 步骤1: 重定向到授权端点
# 浏览器访问：
https://localhost:8080/api/oidc/authorize?response_type=code&client_id=client_123&redirect_uri=https://myapp.com/callback&scope=openid%20profile%20email&state=xyz123&nonce=abc456&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256

# 用户登录后重定向回调：
https://myapp.com/callback?code=auth_code_abc123&state=xyz123

# 步骤2: 交换授权码获取令牌
curl -X POST http://localhost:8080/api/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'grant_type=authorization_code&code=auth_code_abc123&redirect_uri=https://myapp.com/callback&client_id=client_123&client_secret=client_secret_here&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

# 成功响应 (200 OK)
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "def456ghi789jkl012mno345pqr678stu901vwx234yz",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email"
}

# 步骤3: 获取用户信息
curl http://localhost:8080/api/oidc/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 成功响应 (200 OK)
{
  "sub": "user_xyz789",
  "email": "user@example.com",
  "email_verified": true,
  "name": "张三",
  "preferred_username": "user@example.com",
  "updated_at": 1701234567
}
```

#### 刷新令牌
```bash
# 请求
curl -X POST http://localhost:8080/api/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'grant_type=refresh_token&refresh_token=def456ghi789jkl012mno345pqr678stu901vwx234yz&client_id=client_123&client_secret=client_secret_here'

# 成功响应 (200 OK)
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "new_refresh_token_here",
  "scope": "openid profile email"
}
```

#### 单点登出
```bash
# 请求
curl "http://localhost:8080/api/oidc/logout?post_logout_redirect_uri=https://myapp.com/logout&id_token_hint=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...&state=logout_state_123"

# 重定向到：
https://myapp.com/logout?state=logout_state_123
```

#### SSO 会话管理示例
```bash
# 创建 SSO 会话
curl -X POST http://localhost:8080/api/sso/sessions \
  -H "Authorization: Bearer admin-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user_xyz789",
    "client_id": "client_123",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0..."
  }'

# 成功响应 (200 OK)
{
  "session_id": "sso_session_abc123",
  "user_id": "user_xyz789",
  "client_sessions": [
    {
      "client_id": "client_123",
      "session_id": "client_session_def456",
      "created_at": 1701234567,
      "last_accessed_at": 1701234567
    }
  ],
  "created_at": 1701234567,
  "last_accessed_at": 1701234567,
  "expires_at": 1701263367,
  "is_active": true
}

# 获取用户会话统计
curl http://localhost:8080/api/sso/users/user_xyz789/sessions/stats \
  -H "Authorization: Bearer admin-jwt-token"

# 成功响应 (200 OK)
{
  "total_sessions": 2,
  "active_clients": 3,
  "last_activity": 1701234567
}
```

### 安全状态检查示例

#### 检查账户锁定状态
```bash
# 请求
curl http://localhost:8080/api/auth/security/lockout-status \
  -H "Authorization: Bearer your-jwt-token"

# 正常状态响应 (200 OK)
{
  "is_locked": false,
  "remaining_attempts": 3,
  "message": "Account is not locked"
}

# 锁定状态响应 (423 Locked)
{
  "is_locked": true,
  "remaining_attempts": 0,
  "remaining_lockout_seconds": 890,
  "message": "Account locked. Try again in 14 minutes."
}
```

### 安全错误响应示例

#### 速率限制超出
```json
# 429 Too Many Requests
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please try again later.",
  "code": "RATE_LIMIT_EXCEEDED"
}
```

#### 账户锁定
```json
# 423 Locked
{
  "error": "Account locked",
  "message": "Account locked due to multiple failed attempts. Try again in 15 minutes.",
  "locked_until_seconds": 900
}
```

## 安全特性

### 🔐 权限系统（RBAC安全控制）

#### 角色权限管理
- **分层权限设计**: 基于资源和操作的细粒度权限控制
- **系统角色保护**: 预定义系统角色不可删除，确保系统安全
- **灵活角色创建**: 支持自定义角色，满足不同业务需求
- **权限继承**: 用户通过角色获得权限，权限自动聚合
- **实时权限检查**: 毫秒级权限验证，不影响性能

#### 系统角色设计
- **admin**: 系统管理员，拥有所有权限
- **user_manager**: 用户管理员，负责用户管理相关权限
- **security_manager**: 安全管理员，负责安全相关操作权限
- **auditor**: 审计员，只读审计日志权限
- **user**: 普通用户，基础权限

#### 权限保护机制
- **API级别保护**: 所有RBAC接口都需要相应权限才能访问
- **中间件支持**: 提供便捷的权限检查宏和中间件
- **权限验证**: `require_permission!`, `require_role!`, `require_admin!`
- **动态权限**: 支持运行时权限检查和角色变更
- **审计追踪**: 记录所有权限相关操作的审计日志

### 🛡️ 安全防护层（核心安全系统）

#### 速率限制 (Rate Limiting)
- **智能频率控制**: 基于IP和端点的多维度限制
- **自适应规则**: 登录(5次/5分钟)、注册(3次/5分钟)、密码重置(3次/15分钟)
- **内存高效**: 自研缓存系统，定期清理过期记录
- **实时响应**: 毫秒级检查，不影响用户体验
- **防护范围**: 覆盖所有认证相关端点

#### 多因素认证 (MFA)
- **TOTP支持**: 完全兼容Google Authenticator等认证器
- **QR码生成**: SVG格式，支持多种显示方式
- **备用恢复**: 8个一次性使用的恢复代码
- **安全密钥**: Base32编码，20字节强随机密钥
- **生命周期管理**: 设置→验证→启用→使用→禁用完整流程

#### 账户锁定机制
- **多维度保护**: 用户账户 + IP地址双重锁定
- **智能锁定**: 5次失败尝试后锁定15分钟
- **自动解锁**: 时间到期自动解除锁定
- **防暴力破解**: 有效防止密码暴力破解攻击
- **灵活配置**: 可调整尝试次数、锁定时长等参数

#### 安全管理
- **异步处理**: 安全检查不阻塞正常请求流程
- **定期清理**: 每小时自动清理过期安全记录
- **详细日志**: 完整的安全事件记录和追踪
- **状态监控**: 实时安全状态查询接口
- **管理接口**: 支持管理员手动解锁等操作

### 认证安全
- 密码使用 Argon2 加密存储
- JWT 用于会话管理，包含会话ID
- 强制邮箱验证（注册后必须验证才能登录）
- OAuth 用户自动验证
- 安全的JWT密钥管理（强制环境变量配置）

### 会话安全
- 基于数据库的真实会话存储
- 会话主动失效机制（登出功能）
- 支持批量会话管理（全部登出）
- 会话过期时间控制
- 用户设备和IP跟踪

### 密码安全
- 安全的密码重置流程
- 时效性密码重置令牌（1小时过期）
- 一次性使用的重置令牌
- 防止邮箱枚举攻击

### 系统安全
- 敏感信息日志保护
- 数据库连接超时保护
- CSRF 保护准备
- 输入验证和错误处理

## 开发路线图

### 🎉 第一阶段：安全防护层 ✅ (已完成)
- [x] **速率限制系统**: 智能API频率控制，防暴力破解
- [x] **多因素认证**: 完整TOTP/Google Authenticator支持
- [x] **账户锁定机制**: 多维度安全保护，自动锁定解锁
- [x] **安全基础设施**: 实时监控、异步处理、定期清理
- [x] **密码重置功能**: 安全的重置流程
- [x] **会话管理系统**: 完整的会话生命周期管理
- [x] **安全漏洞修复**: JWT密钥管理、敏感信息保护
- [x] **邮箱验证流程**: 强制验证优化

### 🎉 第二阶段：权限系统 ✅ (已完成)
- [x] **RBAC权限系统**: 完整的基于角色的访问控制
- [x] **角色管理**: 创建、编辑、删除角色，支持系统角色保护
- [x] **权限管理**: 基于资源和操作的细粒度权限控制
- [x] **用户角色分配**: 灵活的用户角色分配和移除机制
- [x] **权限检查中间件**: 便捷的权限验证宏和中间件
- [x] **系统角色初始化**: 预定义管理员、用户管理员等系统角色
- [x] **权限保护**: API接口级别的权限控制
- [x] **实时权限验证**: 毫秒级权限检查，支持动态权限变更

### 🎉 第三阶段：用户生命周期管理 ✅ (已完成)
- [x] **完善的用户生命周期管理**: 完整的用户管理体系
- [x] **用户档案管理**: 个人信息、联系方式、头像管理
- [x] **账户状态控制**: 五种状态管理（Active、Inactive、Suspended、PendingDeletion、Deleted）
- [x] **用户偏好设置**: 主题、语言、通知、安全偏好配置
- [x] **用户活动审计**: 详细操作日志、分类管理、查询过滤
- [x] **管理员功能**: 用户列表管理、搜索、状态变更、批量操作
- [x] **登录追踪**: 最后登录时间和IP地址记录
- [x] **权限集成**: 与RBAC系统完全集成的权限控制

### 🎉 第四阶段：监控审计 ✅ (已完成)
- [x] **基础安全日志**: 速率限制、账户锁定、MFA事件记录 ✅
- [x] **登录历史追踪**: IP地址、设备信息记录 ✅  
- [x] **安全仪表板**: 实时安全指标概览和趋势分析 ✅
- [x] **审计日志分析**: 用户活动分类统计和行为分析 ✅
- [x] **安全事件监控**: 失败登录、权限拒绝、可疑活动检测 ✅
- [x] **系统健康监控**: 数据库状态、内存使用、连接池监控 ✅
- [x] **安全报告生成**: 自动生成详细的安全分析报告 ✅
- [x] **威胁检测**: 基于行为模式的异常活动识别 ✅
- [x] **性能指标**: 认证成功率、锁定统计、速率限制违规 ✅
- [x] **风险评估**: 自动风险级别计算和安全建议 ✅

### 🎉 第五阶段：OIDC 单点登录 ✅ (已完成)
- [x] **OIDC 核心协议**: 完整的 OpenID Connect 1.0 实现
- [x] **标准端点**: Discovery、授权、令牌、用户信息、登出端点
- [x] **授权码流程**: 支持 PKCE 的安全授权码流程
- [x] **令牌管理**: 访问令牌、刷新令牌、ID 令牌完整生命周期
- [x] **客户端管理**: 多类型客户端注册、配置、密钥管理
- [x] **SSO 会话**: 跨应用会话同步、单点登出、会话统计
- [x] **安全特性**: PKCE、作用域控制、客户端认证、签名验证
- [x] **兼容性**: 与主流 OIDC 客户端和库完全兼容

### 📋 未来增强功能
- [x] **设备指纹识别**: 基础IP和设备信息追踪 ✅
- [x] **SSO单点登录支持**: 完整的 OIDC 实现 ✅
- [ ] 添加更多OAuth提供商支持 (Apple, Microsoft, Twitter等)
- [ ] 实现账号关联功能（多个OAuth账号关联）
- [ ] 密码复杂度策略和安全建议
- [ ] 高级设备指纹识别和异常检测
- [ ] API密钥管理
- [ ] SAML协议支持

## ⚠️ 重要安全注意事项

### 生产环境部署前必读

1. **JWT密钥安全**
   - `JWT_SECRET` 必须是强随机密钥（至少32字符）
   - 绝不要在代码中硬编码JWT密钥
   - 定期轮换JWT密钥

2. **环境变量配置**
   - 所有敏感配置必须通过环境变量设置
   - 使用 `.env` 文件仅用于开发环境
   - 生产环境使用安全的密钥管理服务

3. **数据库安全**
   - 确保数据库连接使用强密码
   - 启用数据库连接加密
   - 限制数据库访问权限

4. **HTTPS部署**
   - 生产环境必须使用HTTPS
   - 配置安全的TLS证书
   - 启用HSTS等安全头

5. **邮件安全**
   - 使用可信的SMTP服务提供商
   - 配置SPF、DKIM、DMARC记录
   - 监控邮件发送状态

## 贡献

欢迎提交 Pull Request 和 Issue！

## 许可证

MIT License
