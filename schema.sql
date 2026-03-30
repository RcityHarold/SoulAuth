-- Rust Auth System Database Schema
-- 运行此文件以创建所有必需的数据库表和索引

-- 主体表
DEFINE TABLE subject SCHEMAFULL;
DEFINE FIELD subject_type ON subject TYPE string;
DEFINE FIELD created_at ON subject TYPE number;
DEFINE FIELD updated_at ON subject TYPE number;

-- 用户表
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD subject_id ON user TYPE option<record<subject>>;
DEFINE FIELD email ON user TYPE string;
DEFINE FIELD username ON user TYPE string;
DEFINE FIELD username_normalized ON user TYPE string;
DEFINE FIELD password ON user TYPE option<string>;
DEFINE FIELD verified ON user TYPE bool DEFAULT false;
DEFINE FIELD verification_token ON user TYPE option<string>;
DEFINE FIELD account_status ON user TYPE string DEFAULT "Active";
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
DEFINE FIELD user_id ON identity_provider TYPE record<user>;
DEFINE FIELD created_at ON identity_provider TYPE number;
DEFINE FIELD updated_at ON identity_provider TYPE number;
DEFINE INDEX provider_idx ON identity_provider COLUMNS provider, provider_user_id UNIQUE;

-- 会话表
DEFINE TABLE session SCHEMAFULL;
DEFINE FIELD user_id ON session TYPE record<user>;
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
DEFINE FIELD totp_secret ON user_mfa TYPE string;
DEFINE FIELD backup_codes ON user_mfa TYPE array;
DEFINE FIELD created_at ON user_mfa TYPE datetime;
DEFINE FIELD updated_at ON user_mfa TYPE datetime;
DEFINE FIELD last_used_at ON user_mfa TYPE option<datetime>;
DEFINE INDEX user_mfa_user_idx ON user_mfa COLUMNS user_id UNIQUE;

-- 账户锁定表
DEFINE TABLE account_lockout SCHEMAFULL;
DEFINE FIELD identifier ON account_lockout TYPE string;
DEFINE FIELD lockout_type ON account_lockout TYPE string;
DEFINE FIELD failed_attempts ON account_lockout TYPE number;
DEFINE FIELD status ON account_lockout TYPE string;
DEFINE FIELD locked_at ON account_lockout TYPE option<datetime>;
DEFINE FIELD locked_until ON account_lockout TYPE option<datetime>;
DEFINE FIELD last_attempt_at ON account_lockout TYPE option<datetime>;
DEFINE FIELD created_at ON account_lockout TYPE datetime;
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
DEFINE FIELD user_id ON user_role TYPE record<user>;
DEFINE FIELD role_id ON user_role TYPE record<role>;
DEFINE FIELD assigned_at ON user_role TYPE number;
DEFINE FIELD assigned_by ON user_role TYPE record<user>;
DEFINE INDEX user_role_unique_idx ON user_role COLUMNS user_id, role_id UNIQUE;
DEFINE INDEX user_role_user_idx ON user_role COLUMNS user_id;
DEFINE INDEX user_role_role_idx ON user_role COLUMNS role_id;

-- 角色权限关联表
DEFINE TABLE role_permission SCHEMAFULL;
DEFINE FIELD role_id ON role_permission TYPE record<role>;
DEFINE FIELD permission_id ON role_permission TYPE record<permission>;
DEFINE FIELD granted_at ON role_permission TYPE number;
DEFINE FIELD granted_by ON role_permission TYPE record<user>;
DEFINE INDEX role_permission_unique_idx ON role_permission COLUMNS role_id, permission_id UNIQUE;
DEFINE INDEX role_permission_role_idx ON role_permission COLUMNS role_id;
DEFINE INDEX role_permission_permission_idx ON role_permission COLUMNS permission_id;

-- 用户档案表
DEFINE TABLE user_profile SCHEMAFULL;
DEFINE FIELD user_id ON user_profile TYPE record<user>;
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
DEFINE FIELD user_id ON user_preferences TYPE record<user>;
DEFINE FIELD theme ON user_preferences TYPE string DEFAULT "light";
DEFINE FIELD language ON user_preferences TYPE string DEFAULT "en";
DEFINE FIELD email_notifications ON user_preferences TYPE bool DEFAULT true;
DEFINE FIELD sms_notifications ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD marketing_emails ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD security_emails ON user_preferences TYPE bool DEFAULT true;
DEFINE FIELD newsletter ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD two_factor_required ON user_preferences TYPE bool DEFAULT false;
DEFINE FIELD session_timeout ON user_preferences TYPE number DEFAULT 86400;
DEFINE FIELD timezone ON user_preferences TYPE string DEFAULT "UTC";
DEFINE FIELD date_format ON user_preferences TYPE string DEFAULT "YYYY-MM-DD";
DEFINE FIELD time_format ON user_preferences TYPE string DEFAULT "24h";
DEFINE FIELD created_at ON user_preferences TYPE number;
DEFINE FIELD updated_at ON user_preferences TYPE number;
DEFINE INDEX user_preferences_user_idx ON user_preferences COLUMNS user_id UNIQUE;

-- 用户活动日志表
DEFINE TABLE user_activity SCHEMAFULL;
DEFINE FIELD user_id ON user_activity TYPE record<user>;
DEFINE FIELD action ON user_activity TYPE string;
DEFINE FIELD category ON user_activity TYPE string;
DEFINE FIELD ip_address ON user_activity TYPE string;
DEFINE FIELD user_agent ON user_activity TYPE string;
DEFINE FIELD details ON user_activity TYPE object;
DEFINE FIELD status ON user_activity TYPE string;
DEFINE FIELD timestamp ON user_activity TYPE number;
DEFINE INDEX user_activity_user_idx ON user_activity COLUMNS user_id;
DEFINE INDEX user_activity_timestamp_idx ON user_activity COLUMNS timestamp;
DEFINE INDEX user_activity_category_idx ON user_activity COLUMNS category;

-- 好友申请表
DEFINE TABLE friend_request SCHEMAFULL;
DEFINE FIELD requester_id ON friend_request TYPE record<user>;
DEFINE FIELD addressee_id ON friend_request TYPE record<user>;
DEFINE FIELD status ON friend_request TYPE string DEFAULT "Pending";
DEFINE FIELD message ON friend_request TYPE option<string>;
DEFINE FIELD created_at ON friend_request TYPE number;
DEFINE FIELD responded_at ON friend_request TYPE option<number>;
DEFINE INDEX friend_request_lookup_idx ON friend_request COLUMNS requester_id, addressee_id, status;
DEFINE INDEX friend_request_addressee_idx ON friend_request COLUMNS addressee_id, status, created_at;

-- 好友关系表
DEFINE TABLE friendship SCHEMAFULL;
DEFINE FIELD user_a ON friendship TYPE record<user>;
DEFINE FIELD user_b ON friendship TYPE record<user>;
DEFINE FIELD created_at ON friendship TYPE number;
DEFINE FIELD created_from_request_id ON friendship TYPE option<record<friend_request>>;
DEFINE INDEX friendship_unique_idx ON friendship COLUMNS user_a, user_b UNIQUE;
DEFINE INDEX friendship_user_a_idx ON friendship COLUMNS user_a;
DEFINE INDEX friendship_user_b_idx ON friendship COLUMNS user_b;

-- 人类私聊会话表
DEFINE TABLE direct_conversation SCHEMAFULL;
DEFINE FIELD user_a ON direct_conversation TYPE record<user>;
DEFINE FIELD user_b ON direct_conversation TYPE record<user>;
DEFINE FIELD created_at ON direct_conversation TYPE number;
DEFINE FIELD updated_at ON direct_conversation TYPE number;
DEFINE INDEX direct_conversation_unique_idx ON direct_conversation COLUMNS user_a, user_b UNIQUE;
DEFINE INDEX direct_conversation_user_a_idx ON direct_conversation COLUMNS user_a, updated_at;
DEFINE INDEX direct_conversation_user_b_idx ON direct_conversation COLUMNS user_b, updated_at;

-- 人类私聊消息表
DEFINE TABLE direct_message SCHEMAFULL;
DEFINE FIELD conversation_id ON direct_message TYPE record<direct_conversation>;
DEFINE FIELD sender_id ON direct_message TYPE record<user>;
DEFINE FIELD recipient_id ON direct_message TYPE record<user>;
DEFINE FIELD content ON direct_message TYPE string;
DEFINE FIELD created_at ON direct_message TYPE number;
DEFINE INDEX direct_message_conversation_idx ON direct_message COLUMNS conversation_id, created_at;
DEFINE INDEX direct_message_recipient_idx ON direct_message COLUMNS recipient_id, created_at;

-- 社交群组表
DEFINE TABLE social_group SCHEMAFULL;
DEFINE FIELD name ON social_group TYPE string;
DEFINE FIELD avatar ON social_group TYPE string;
DEFINE FIELD type ON social_group TYPE number;
DEFINE FIELD level ON social_group TYPE string;
DEFINE FIELD ownerId ON social_group TYPE string;
DEFINE FIELD created_at ON social_group TYPE string;
DEFINE FIELD admin_ids ON social_group TYPE array;
DEFINE FIELD member_ids ON social_group TYPE array;
DEFINE FIELD announcement ON social_group TYPE option<string>;
DEFINE FIELD settings ON social_group TYPE option<object>;
DEFINE FIELD settings.join_mode ON social_group TYPE string;
DEFINE FIELD settings.allow_member_invite ON social_group TYPE bool;
DEFINE FIELD settings.allow_file_upload ON social_group TYPE bool;
DEFINE FIELD code ON social_group TYPE option<string>;
DEFINE FIELD human_member_ids ON social_group TYPE array;
DEFINE FIELD ai_member_ids ON social_group TYPE array;
DEFINE FIELD description ON social_group TYPE option<string>;
DEFINE FIELD max_humans ON social_group TYPE option<number>;
DEFINE FIELD max_ais ON social_group TYPE option<number>;
DEFINE FIELD member_user_ids ON social_group TYPE array;
DEFINE INDEX social_group_owner_idx ON social_group COLUMNS ownerId;

DEFINE TABLE social_group_member SCHEMAFULL;
DEFINE FIELD group_id ON social_group_member TYPE string;
DEFINE FIELD member_id ON social_group_member TYPE string;
DEFINE FIELD member_kind ON social_group_member TYPE string;
DEFINE FIELD created_at ON social_group_member TYPE string;
DEFINE INDEX social_group_member_lookup_idx ON social_group_member COLUMNS group_id, member_id, member_kind UNIQUE;
DEFINE INDEX social_group_member_member_idx ON social_group_member COLUMNS member_id, member_kind;

DEFINE TABLE group_thread SCHEMAFULL;
DEFINE FIELD group_id ON group_thread TYPE string;
DEFINE FIELD thread_type ON group_thread TYPE string;
DEFINE FIELD title ON group_thread TYPE string;
DEFINE FIELD created_by ON group_thread TYPE string;
DEFINE FIELD status ON group_thread TYPE string;
DEFINE FIELD created_at ON group_thread TYPE string;
DEFINE FIELD updated_at ON group_thread TYPE string;
DEFINE INDEX group_thread_group_idx ON group_thread COLUMNS group_id, updated_at;

DEFINE TABLE group_thread_message SCHEMAFULL;
DEFINE FIELD group_id ON group_thread_message TYPE string;
DEFINE FIELD thread_id ON group_thread_message TYPE string;
DEFINE FIELD sender_id ON group_thread_message TYPE string;
DEFINE FIELD sender_kind ON group_thread_message TYPE string;
DEFINE FIELD message_type ON group_thread_message TYPE string;
DEFINE FIELD content ON group_thread_message TYPE string;
DEFINE FIELD reply_to ON group_thread_message TYPE option<string>;
DEFINE FIELD created_at ON group_thread_message TYPE string;
DEFINE INDEX group_thread_message_thread_idx ON group_thread_message COLUMNS thread_id, created_at;

DEFINE TABLE group_collab_run SCHEMAFULL;
DEFINE FIELD group_id ON group_collab_run TYPE string;
DEFINE FIELD thread_id ON group_collab_run TYPE string;
DEFINE FIELD scenario_type ON group_collab_run TYPE number;
DEFINE FIELD triggered_by ON group_collab_run TYPE string;
DEFINE FIELD strategy_type ON group_collab_run TYPE string;
DEFINE FIELD status ON group_collab_run TYPE string;
DEFINE FIELD prompt ON group_collab_run TYPE string;
DEFINE FIELD participant_ids ON group_collab_run TYPE array;
DEFINE FIELD metadata ON group_collab_run TYPE option<object>;
DEFINE FIELD result_summary ON group_collab_run TYPE option<string>;
DEFINE FIELD result_payload ON group_collab_run TYPE option<object>;
DEFINE FIELD created_at ON group_collab_run TYPE string;
DEFINE FIELD updated_at ON group_collab_run TYPE string;
DEFINE FIELD completed_at ON group_collab_run TYPE option<string>;
DEFINE INDEX group_collab_run_thread_idx ON group_collab_run COLUMNS thread_id, created_at;

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
DEFINE FIELD created_by ON oidc_client TYPE record<user>;
DEFINE FIELD created_at ON oidc_client TYPE number;
DEFINE FIELD updated_at ON oidc_client TYPE number;
DEFINE INDEX oidc_client_id_idx ON oidc_client COLUMNS client_id UNIQUE;

-- OIDC 授权码表
DEFINE TABLE oidc_authorization_code SCHEMAFULL;
DEFINE FIELD code ON oidc_authorization_code TYPE string;
DEFINE FIELD client_id ON oidc_authorization_code TYPE string;
DEFINE FIELD user_id ON oidc_authorization_code TYPE record<user>;
DEFINE FIELD redirect_uri ON oidc_authorization_code TYPE string;
DEFINE FIELD scope ON oidc_authorization_code TYPE string;
DEFINE FIELD state ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD nonce ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD code_challenge ON oidc_authorization_code TYPE option<string>;
DEFINE FIELD code_challenge_method ON oidc_authorization_code TYPE option<string>;
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
DEFINE FIELD user_id ON oidc_access_token TYPE record<user>;
DEFINE FIELD scope ON oidc_access_token TYPE string;
DEFINE FIELD expires_at ON oidc_access_token TYPE number;
DEFINE FIELD created_at ON oidc_access_token TYPE number;
DEFINE INDEX oidc_access_token_idx ON oidc_access_token COLUMNS token UNIQUE;
DEFINE INDEX oidc_access_token_expiry_idx ON oidc_access_token COLUMNS expires_at;

-- OIDC 刷新令牌表
DEFINE TABLE oidc_refresh_token SCHEMAFULL;
DEFINE FIELD token ON oidc_refresh_token TYPE string;
DEFINE FIELD client_id ON oidc_refresh_token TYPE string;
DEFINE FIELD user_id ON oidc_refresh_token TYPE record<user>;
DEFINE FIELD access_token ON oidc_refresh_token TYPE string; -- 关联的访问令牌
DEFINE FIELD scope ON oidc_refresh_token TYPE string;
DEFINE FIELD used ON oidc_refresh_token TYPE bool DEFAULT false;
DEFINE FIELD expires_at ON oidc_refresh_token TYPE number;
DEFINE FIELD created_at ON oidc_refresh_token TYPE number;
DEFINE INDEX oidc_refresh_token_idx ON oidc_refresh_token COLUMNS token UNIQUE;
DEFINE INDEX oidc_refresh_token_expiry_idx ON oidc_refresh_token COLUMNS expires_at;

-- SSO 会话表
DEFINE TABLE sso_session SCHEMAFULL;
DEFINE FIELD session_id ON sso_session TYPE string;
DEFINE FIELD user_id ON sso_session TYPE record<user>;
DEFINE FIELD client_sessions ON sso_session TYPE array; -- 客户端会话列表
DEFINE FIELD created_at ON sso_session TYPE number;
DEFINE FIELD last_accessed_at ON sso_session TYPE number;
DEFINE FIELD expires_at ON sso_session TYPE number;
DEFINE FIELD ip_address ON sso_session TYPE string;
DEFINE FIELD user_agent ON sso_session TYPE string;
DEFINE INDEX sso_session_id_idx ON sso_session COLUMNS session_id UNIQUE;
DEFINE INDEX sso_session_user_idx ON sso_session COLUMNS user_id;
DEFINE INDEX sso_session_expiry_idx ON sso_session COLUMNS expires_at;
