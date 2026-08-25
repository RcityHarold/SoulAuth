-- SoulAuth Database Schema
-- 运行此文件以创建所有必需的数据库表和索引

-- ═══════════════════════════════════════════════════════════════════
-- Actor Identity Domain
-- ═══════════════════════════════════════════════════════════════════
--
-- 身份根是 `actor_identity`，不是 `user`。
--
-- Human 与 AIActor 都是一等身份主体，通过同一套 Actor Identity Contract
-- 进入系统；它们可以拥有不同的 Credential、Authentication Method 与
-- Lifecycle，但没有哪一个需要伪装成另一个才能被认证。
--
-- 五个对象永远不能重新合并（GA-01 §4，GA-07 §13）：
--
--   ActorIdentity    谁？
--   HumanAccount     Human 怎样管理自己的登录账户？
--   IdentityBinding  外部某个身份如何证明与该 Actor 是同一主体？
--   Credential       Actor 用什么证明自己？        （Stage 2 收口）
--   Client           哪个软件正在请求身份能力？     （见 oidc_client）

-- 身份根。回答「谁是这个可以被认证的主体」，仅此而已。
DEFINE TABLE actor_identity SCHEMAFULL;

-- 对外稳定的 Authentication Subject。
--
-- OIDC `sub` 建立在它之上。Email、Username、Display Name 的修改，Credential
-- 的轮换，MFA 的增减，经由不同 Client 进入 —— 这些都不得改变它（GA-04 §7）。
--
-- 它与 record id 是**两个命名空间**。实现上可以取同一个值，但那是实现选择，
-- 不建立语义等同（GA-04 §5）：文档不得声称 `Resource ID = Stable Subject`。
DEFINE FIELD subject_key ON actor_identity TYPE string;

-- `human` | `ai_actor`
--
-- 第一阶段只承认这两类。Organization、Device、Application 要进入同一套
-- Actor Identity Contract，必须经过正式架构裁决，而不是因为加一个 enum
-- 变体很容易就加上（GA-01 §4）。
DEFINE FIELD actor_kind ON actor_identity TYPE string;

-- `local` | `soulseed` | `external`
--
-- 这个身份通过什么受控来源进入 SoulAuth。它不替代 IdentityBinding，
-- 也不意味着一个 Actor 只能有一条外部身份关系（GA-01 §4）。
DEFINE FIELD identity_source ON actor_identity TYPE string DEFAULT "local";

-- Soulseed 模式下绑定 SoulseedAGI 已经成立的 Canonical Actor。
--
-- 它只是一条受控引用：证明绑定关系，**不赋予** SoulAuth 定义或修改
-- Mind / SubjectIntent / Memory 的能力（GA-01 §11，GA-07 §9）。
-- 也不得默认暴露给第三方 OIDC Client —— 属受控 Integration Claim。
DEFINE FIELD canonical_actor_ref ON actor_identity TYPE option<string>;

-- `active` | `suspended` | `retired`
--
-- Retired 可以停止认证，但其 subject_key **不得**被重新分配给另一个 Actor：
-- 否则历史 Claims、Audit 与外部记录里的同一个 Subject，会在不同时间指向
-- 不同主体（GA-04 §12，06 §7）。
DEFINE FIELD status ON actor_identity TYPE string DEFAULT "active";

DEFINE FIELD created_at ON actor_identity TYPE number;
DEFINE FIELD updated_at ON actor_identity TYPE number;

DEFINE INDEX actor_subject_idx ON actor_identity COLUMNS subject_key UNIQUE;
DEFINE INDEX actor_kind_idx ON actor_identity COLUMNS actor_kind;
-- Canonical 绑定必须唯一：两个 ActorIdentity 绑到同一个 Canonical Actor，
-- 等于在 SoulAuth 里把一个主体分裂成两个。
DEFINE INDEX actor_canonical_ref_idx ON actor_identity COLUMNS canonical_actor_ref UNIQUE;

-- Human-specific account extension。**不是身份根。**
--
-- Human 修改 Email 不意味着 ActorIdentity 发生变化。AIActor 不需要为了
-- 拥有身份而伪造 Email / Username（GA-01 §4，GA-07 §13）。
--
-- Password 不在这里：它属于 Credential Domain。当前仍暂留在 `user` 表上，
-- Stage 2 收口。
DEFINE TABLE human_account SCHEMAFULL;
DEFINE FIELD actor_identity_id ON human_account TYPE record<actor_identity>;
DEFINE FIELD email ON human_account TYPE string;
DEFINE FIELD username ON human_account TYPE string;
DEFINE FIELD username_normalized ON human_account TYPE string;
DEFINE FIELD email_verified ON human_account TYPE bool DEFAULT false;
DEFINE FIELD created_at ON human_account TYPE number;
DEFINE FIELD updated_at ON human_account TYPE number;

DEFINE INDEX human_account_email_idx ON human_account COLUMNS email UNIQUE;
DEFINE INDEX human_account_username_idx ON human_account COLUMNS username_normalized UNIQUE;
-- 一个 Human ActorIdentity 至多一个账户。
DEFINE INDEX human_account_actor_idx ON human_account COLUMNS actor_identity_id UNIQUE;

-- 外部身份来源与本地 ActorIdentity 之间**经过验证的**对应关系。
--
-- 它是独立关系对象，不是 ActorIdentity 里的一个外部 ID 字段。
-- Google、GitHub、企业 IdP 与 Soulseed Canonical Actor 共享同一抽象 ——
-- 不需要为「机器人账号」另造一套（GA-01 §4，GA-07 §9）。
--
-- 关键边界：Binding 建立关系，但**不创造上游主体**。Google Identity 由
-- Google 定义，Canonical AIActor 由 SoulseedAGI 定义。
--
-- 也不等于 Credential：外部 IdP 里 Human 用的密码不会因此成为 SoulAuth 的
-- Actor Credential（GA-05 §4）。
DEFINE TABLE identity_binding SCHEMAFULL;
DEFINE FIELD actor_identity_id ON identity_binding TYPE record<actor_identity>;
DEFINE FIELD provider ON identity_binding TYPE string;
DEFINE FIELD provider_subject ON identity_binding TYPE string;
-- `federated` | `canonical` —— 前者是外部 IdP，后者是 Soulseed Canonical Actor。
DEFINE FIELD binding_type ON identity_binding TYPE string DEFAULT "federated";
-- `verified` | `pending` | `revoked`
DEFINE FIELD verification_state ON identity_binding TYPE string DEFAULT "verified";
DEFINE FIELD bound_at ON identity_binding TYPE number;
DEFINE FIELD revoked_at ON identity_binding TYPE option<number>;

-- (provider, provider_subject) 必须联合唯一。
--
-- 只按 subject 唯一是一个真实的跨 provider 账号接管：数字 id 为 4001 的
-- GitHub 账号会匹配上 sub 为字符串 "4001" 的 Google 用户。
DEFINE INDEX identity_binding_provider_subject_idx
    ON identity_binding COLUMNS provider, provider_subject UNIQUE;
DEFINE INDEX identity_binding_actor_idx ON identity_binding COLUMNS actor_identity_id;

-- ═══════════════════════════════════════════════════════════════════
-- 以下为 V1 遗留，Stage 2/3 逐步迁出
-- ═══════════════════════════════════════════════════════════════════

-- 主体表（V1）。已被 actor_identity.actor_kind 取代，Stage 4 删除。
DEFINE TABLE subject SCHEMAFULL;
DEFINE FIELD subject_type ON subject TYPE string;
DEFINE FIELD created_at ON subject TYPE number;
DEFINE FIELD updated_at ON subject TYPE number;

-- 用户表（V1）
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD subject_id ON user TYPE option<record<subject>>;
DEFINE FIELD email ON user TYPE string;
DEFINE FIELD username ON user TYPE string;
DEFINE FIELD username_normalized ON user TYPE string;
DEFINE FIELD password ON user TYPE option<string>;
DEFINE FIELD verified ON user TYPE bool DEFAULT false;
DEFINE FIELD verification_token ON user TYPE option<string>;
DEFINE FIELD verification_token_expires_at ON user TYPE option<number>;
DEFINE FIELD account_status ON user TYPE string DEFAULT "Active";
DEFINE FIELD membership_level ON user TYPE string DEFAULT "FREE";
-- 时间点而非自由字符串：形状由 SoulAuth 保证，语义（过期与否）由消费方解释。
DEFINE FIELD membership_expiry ON user TYPE option<datetime>;
DEFINE FIELD last_login_at ON user TYPE option<number>;
DEFINE FIELD last_login_ip ON user TYPE option<string>;
DEFINE FIELD created_at ON user TYPE number;
DEFINE FIELD updated_at ON user TYPE number;
DEFINE INDEX email_idx ON user COLUMNS email UNIQUE;
DEFINE INDEX username_idx ON user COLUMNS username_normalized UNIQUE;

-- 身份提供商表
DEFINE TABLE identity_provider SCHEMAFULL;
DEFINE FIELD provider ON identity_provider TYPE string;
DEFINE FIELD provider_user_id ON identity_provider TYPE string;
DEFINE FIELD user_id ON identity_provider TYPE record<actor_identity>;
DEFINE FIELD created_at ON identity_provider TYPE number;
DEFINE FIELD updated_at ON identity_provider TYPE number;
DEFINE INDEX provider_idx ON identity_provider COLUMNS provider, provider_user_id UNIQUE;

-- 会话表
DEFINE TABLE session SCHEMAFULL;
DEFINE FIELD user_id ON session TYPE record<actor_identity>;
DEFINE FIELD token ON session TYPE string;
DEFINE FIELD expires_at ON session TYPE number;
DEFINE FIELD created_at ON session TYPE number;
DEFINE FIELD user_agent ON session TYPE string;
DEFINE FIELD ip_address ON session TYPE string;
DEFINE INDEX token_idx ON session COLUMNS token UNIQUE;

-- 密码重置令牌表
DEFINE TABLE password_reset_token SCHEMAFULL;
DEFINE FIELD email ON password_reset_token TYPE string;
DEFINE FIELD token ON password_reset_token TYPE string;
DEFINE FIELD expires_at ON password_reset_token TYPE datetime;
DEFINE FIELD used ON password_reset_token TYPE bool;
DEFINE FIELD created_at ON password_reset_token TYPE datetime;
DEFINE INDEX reset_token_idx ON password_reset_token COLUMNS token UNIQUE;
DEFINE INDEX reset_email_idx ON password_reset_token COLUMNS email;

-- 多因素认证表
DEFINE TABLE user_mfa SCHEMAFULL;
DEFINE FIELD user_id ON user_mfa TYPE string;
DEFINE FIELD status ON user_mfa TYPE string;
DEFINE FIELD method ON user_mfa TYPE string;
-- 模型侧是 Option<String>（SMS / Email 方式下没有 TOTP 密钥），
-- schema 必须同为可空，否则写入 None 会被拒。
DEFINE FIELD totp_secret ON user_mfa TYPE option<string>;
DEFINE FIELD backup_codes ON user_mfa TYPE array;
DEFINE FIELD created_at ON user_mfa TYPE datetime;
DEFINE FIELD updated_at ON user_mfa TYPE datetime;
DEFINE FIELD last_used_at ON user_mfa TYPE option<datetime>;
-- 已接受过的 TOTP 时间步，用于拒绝同一个码在窗口内被重放（RFC 6238 §5.2）。
DEFINE FIELD last_totp_step ON user_mfa TYPE option<number>;
DEFINE INDEX user_mfa_user_idx ON user_mfa COLUMNS user_id UNIQUE;

-- 账户锁定表
DEFINE TABLE account_lockout SCHEMAFULL;
DEFINE FIELD identifier ON account_lockout TYPE string;
DEFINE FIELD lockout_type ON account_lockout TYPE string;
DEFINE FIELD failed_attempts ON account_lockout TYPE number;
-- DEFAULT 是必须的：`increment_failed_attempts` 首次插入时只 SET 计数相关字段，
-- 不碰 status（碰了会把已锁定的记录改回 Normal）。
DEFINE FIELD status ON account_lockout TYPE string DEFAULT 'Normal';
DEFINE FIELD locked_at ON account_lockout TYPE option<datetime>;
DEFINE FIELD locked_until ON account_lockout TYPE option<datetime>;
DEFINE FIELD last_attempt_at ON account_lockout TYPE option<datetime>;
DEFINE FIELD created_at ON account_lockout TYPE datetime DEFAULT time::now();
DEFINE FIELD updated_at ON account_lockout TYPE datetime;
DEFINE INDEX lockout_identifier_idx ON account_lockout COLUMNS identifier, lockout_type UNIQUE;

-- 角色表
DEFINE TABLE role SCHEMAFULL;
DEFINE FIELD name ON role TYPE string;
DEFINE FIELD display_name ON role TYPE string;
DEFINE FIELD description ON role TYPE option<string>;
DEFINE FIELD is_system ON role TYPE bool;
DEFINE FIELD created_at ON role TYPE number;
DEFINE FIELD updated_at ON role TYPE number;
DEFINE INDEX role_name_idx ON role COLUMNS name UNIQUE;

-- 权限表
DEFINE TABLE permission SCHEMAFULL;
DEFINE FIELD name ON permission TYPE string;
DEFINE FIELD display_name ON permission TYPE string;
DEFINE FIELD description ON permission TYPE option<string>;
DEFINE FIELD resource ON permission TYPE string;
DEFINE FIELD action ON permission TYPE string;
DEFINE FIELD is_system ON permission TYPE bool;
DEFINE FIELD created_at ON permission TYPE number;
DEFINE FIELD updated_at ON permission TYPE number;
DEFINE INDEX permission_name_idx ON permission COLUMNS name UNIQUE;
DEFINE INDEX permission_resource_action_idx ON permission COLUMNS resource, action;

-- 用户角色关联表
DEFINE TABLE user_role SCHEMAFULL;
DEFINE FIELD user_id ON user_role TYPE record<actor_identity>;
DEFINE FIELD role_id ON user_role TYPE record<role>;
DEFINE FIELD assigned_at ON user_role TYPE number;
DEFINE FIELD assigned_by ON user_role TYPE record<actor_identity>;
DEFINE INDEX user_role_unique_idx ON user_role COLUMNS user_id, role_id UNIQUE;
DEFINE INDEX user_role_user_idx ON user_role COLUMNS user_id;
DEFINE INDEX user_role_role_idx ON user_role COLUMNS role_id;

-- 角色权限关联表
DEFINE TABLE role_permission SCHEMAFULL;
DEFINE FIELD role_id ON role_permission TYPE record<role>;
DEFINE FIELD permission_id ON role_permission TYPE record<permission>;
DEFINE FIELD granted_at ON role_permission TYPE number;
DEFINE FIELD granted_by ON role_permission TYPE record<actor_identity>;
DEFINE INDEX role_permission_unique_idx ON role_permission COLUMNS role_id, permission_id UNIQUE;
DEFINE INDEX role_permission_role_idx ON role_permission COLUMNS role_id;
DEFINE INDEX role_permission_permission_idx ON role_permission COLUMNS permission_id;

-- 用户档案表
DEFINE TABLE user_profile SCHEMAFULL;
DEFINE FIELD user_id ON user_profile TYPE record<actor_identity>;
DEFINE FIELD first_name ON user_profile TYPE option<string>;
DEFINE FIELD last_name ON user_profile TYPE option<string>;
DEFINE FIELD display_name ON user_profile TYPE option<string>;
DEFINE FIELD avatar_url ON user_profile TYPE option<string>;
DEFINE FIELD phone ON user_profile TYPE option<string>;
DEFINE FIELD date_of_birth ON user_profile TYPE option<datetime>;
DEFINE FIELD timezone ON user_profile TYPE option<string>;
DEFINE FIELD locale ON user_profile TYPE option<string>;
DEFINE FIELD bio ON user_profile TYPE option<string>;
DEFINE FIELD website ON user_profile TYPE option<string>;
DEFINE FIELD location ON user_profile TYPE option<string>;
DEFINE FIELD created_at ON user_profile TYPE number;
DEFINE FIELD updated_at ON user_profile TYPE number;
DEFINE INDEX user_profile_user_idx ON user_profile COLUMNS user_id UNIQUE;

-- 用户偏好表
DEFINE TABLE user_preferences SCHEMAFULL;
DEFINE FIELD user_id ON user_preferences TYPE record<actor_identity>;
DEFINE FIELD theme ON user_preferences TYPE string DEFAULT "light";
DEFINE FIELD language ON user_preferences TYPE string DEFAULT "en";
DEFINE FIELD email_notifications ON user_preferences TYPE bool DEFAULT true;
DEFINE FIELD sms_notifications ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD marketing_emails ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD security_emails ON user_preferences TYPE bool DEFAULT true;
DEFINE FIELD newsletter ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD timezone ON user_preferences TYPE string DEFAULT "UTC";
DEFINE FIELD date_format ON user_preferences TYPE string DEFAULT "YYYY-MM-DD";
DEFINE FIELD time_format ON user_preferences TYPE string DEFAULT "24h";
DEFINE FIELD created_at ON user_preferences TYPE number;
DEFINE FIELD updated_at ON user_preferences TYPE number;
DEFINE INDEX user_preferences_user_idx ON user_preferences COLUMNS user_id UNIQUE;

-- 用户活动日志表
DEFINE TABLE user_activity SCHEMAFULL;
-- 登录失败、限流触发这类事件未必对应一个已存在的用户，故为可选。
DEFINE FIELD user_id ON user_activity TYPE option<record<actor_identity>>;
DEFINE FIELD action ON user_activity TYPE string;
DEFINE FIELD category ON user_activity TYPE string;
DEFINE FIELD ip_address ON user_activity TYPE string;
DEFINE FIELD user_agent ON user_activity TYPE string;
-- details 是按事件类型变化的自由结构（reason / provider / permission / endpoint ...）。
-- SCHEMAFULL 表上必须显式放开嵌套键，否则写入会被拒：
--   "Found field 'details.endpoint', but no such field exists for table 'user_activity'"
DEFINE FIELD details ON user_activity TYPE object;
DEFINE FIELD details.* ON user_activity TYPE any;
DEFINE FIELD status ON user_activity TYPE string;
DEFINE FIELD timestamp ON user_activity TYPE number;
DEFINE INDEX user_activity_user_idx ON user_activity COLUMNS user_id;
DEFINE INDEX user_activity_timestamp_idx ON user_activity COLUMNS timestamp;
DEFINE INDEX user_activity_category_idx ON user_activity COLUMNS category;

-- ===============================
-- OIDC SSO 相关表结构
-- ===============================

-- OIDC 客户端应用表
DEFINE TABLE oidc_client SCHEMAFULL;
DEFINE FIELD client_id ON oidc_client TYPE string;
DEFINE FIELD client_secret_hash ON oidc_client TYPE string;
DEFINE FIELD client_name ON oidc_client TYPE string;
DEFINE FIELD client_type ON oidc_client TYPE string; -- public, confidential
DEFINE FIELD redirect_uris ON oidc_client TYPE array;
DEFINE FIELD post_logout_redirect_uris ON oidc_client TYPE array;
DEFINE FIELD allowed_scopes ON oidc_client TYPE array;
DEFINE FIELD allowed_grant_types ON oidc_client TYPE array;
DEFINE FIELD allowed_response_types ON oidc_client TYPE array;
DEFINE FIELD require_pkce ON oidc_client TYPE bool DEFAULT true;
DEFINE FIELD access_token_lifetime ON oidc_client TYPE number DEFAULT 3600; -- 1小时
DEFINE FIELD refresh_token_lifetime ON oidc_client TYPE number DEFAULT 86400; -- 24小时
DEFINE FIELD id_token_lifetime ON oidc_client TYPE number DEFAULT 3600; -- 1小时
DEFINE FIELD is_active ON oidc_client TYPE bool DEFAULT true;
DEFINE FIELD created_by ON oidc_client TYPE string;
DEFINE FIELD created_at ON oidc_client TYPE number;
DEFINE FIELD updated_at ON oidc_client TYPE number;
DEFINE INDEX oidc_client_id_idx ON oidc_client COLUMNS client_id UNIQUE;

-- OIDC 授权码表
DEFINE TABLE oidc_authorization_code SCHEMAFULL;
DEFINE FIELD code ON oidc_authorization_code TYPE string;
DEFINE FIELD client_id ON oidc_authorization_code TYPE string;
DEFINE FIELD user_id ON oidc_authorization_code TYPE record<actor_identity>;
DEFINE FIELD redirect_uri ON oidc_authorization_code TYPE string;
DEFINE FIELD scope ON oidc_authorization_code TYPE string;
DEFINE FIELD state ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD nonce ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD code_challenge ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD code_challenge_method ON oidc_authorization_code TYPE option<string>;
-- 签发时的 SoulAuth 认证会话主键，用于把 sid 带到 ID Token（P0-DECISION-10）。
DEFINE FIELD auth_session_ref ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD used ON oidc_authorization_code TYPE bool DEFAULT false;
DEFINE FIELD expires_at ON oidc_authorization_code TYPE number;
DEFINE FIELD created_at ON oidc_authorization_code TYPE number;
DEFINE INDEX oidc_auth_code_idx ON oidc_authorization_code COLUMNS code UNIQUE;
DEFINE INDEX oidc_auth_code_expiry_idx ON oidc_authorization_code COLUMNS expires_at;

-- OIDC 访问令牌表
DEFINE TABLE oidc_access_token SCHEMAFULL;
DEFINE FIELD token ON oidc_access_token TYPE string;
DEFINE FIELD token_type ON oidc_access_token TYPE string DEFAULT "Bearer";
DEFINE FIELD client_id ON oidc_access_token TYPE string;
DEFINE FIELD user_id ON oidc_access_token TYPE record<actor_identity>;
DEFINE FIELD scope ON oidc_access_token TYPE string;
DEFINE FIELD expires_at ON oidc_access_token TYPE number;
DEFINE FIELD created_at ON oidc_access_token TYPE number;
DEFINE INDEX oidc_access_token_idx ON oidc_access_token COLUMNS token UNIQUE;
DEFINE INDEX oidc_access_token_expiry_idx ON oidc_access_token COLUMNS expires_at;

-- OIDC 刷新令牌表
DEFINE TABLE oidc_refresh_token SCHEMAFULL;
DEFINE FIELD token ON oidc_refresh_token TYPE string;
DEFINE FIELD client_id ON oidc_refresh_token TYPE string;
DEFINE FIELD user_id ON oidc_refresh_token TYPE record<actor_identity>;
DEFINE FIELD access_token ON oidc_refresh_token TYPE string; -- 关联的访问令牌
DEFINE FIELD scope ON oidc_refresh_token TYPE string;
-- 同上：刷新也会签 ID Token，sid 必须能继续传递。
DEFINE FIELD auth_session_ref ON oidc_refresh_token TYPE option<string>;
DEFINE FIELD used ON oidc_refresh_token TYPE bool DEFAULT false;
DEFINE FIELD expires_at ON oidc_refresh_token TYPE number;
DEFINE FIELD created_at ON oidc_refresh_token TYPE number;
DEFINE INDEX oidc_refresh_token_idx ON oidc_refresh_token COLUMNS token UNIQUE;
DEFINE INDEX oidc_refresh_token_expiry_idx ON oidc_refresh_token COLUMNS expires_at;

-- 跨副本共享的限流计数桶。
-- 记录 ID 是 (客户端标识, 端点) 的摘要；window_index 为固定窗口序号，
-- 换窗口即清零，因此不需要保留时间戳列表。
DEFINE TABLE IF NOT EXISTS rate_limit SCHEMALESS;
DEFINE FIELD IF NOT EXISTS hits ON rate_limit TYPE number DEFAULT 0;
DEFINE FIELD IF NOT EXISTS window_index ON rate_limit TYPE number DEFAULT 0;
DEFINE FIELD IF NOT EXISTS client_key ON rate_limit TYPE option<string>;
DEFINE FIELD IF NOT EXISTS endpoint ON rate_limit TYPE option<string>;
DEFINE FIELD IF NOT EXISTS blocked_until ON rate_limit TYPE option<datetime>;
DEFINE FIELD IF NOT EXISTS updated_at ON rate_limit TYPE option<datetime>;
DEFINE INDEX IF NOT EXISTS rate_limit_updated ON rate_limit FIELDS updated_at;
