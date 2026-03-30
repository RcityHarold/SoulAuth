use crate::{
    config::Config,
    error::{AuthError, Result},
    models::{
        user::{User, CreateUserRequest, AuthResponse, UserResponse},
        subject::{Subject, SubjectType},
        identity_provider::{IdentityProvider, OAuthUserInfo},
        password_reset::{PasswordResetToken, RequestPasswordResetRequest, ResetPasswordRequest},
        session::{Session, SessionInfo},
    },
    services::{
        database::Database,
        email::EmailService,
        oauth::OAuthService,
    },
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::sync::Arc;
use surrealdb::types::RecordId as Thing;
use tracing::{error, info, debug};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
    iat: i64,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    subject_type: Option<SubjectType>,
}

pub struct AuthService {
    db: Arc<Database>,
    config: Config,
    email_service: EmailService,
    oauth_service: OAuthService,
}

fn new_thing(table: &str) -> Thing {
    Thing::new(table, Uuid::new_v4().to_string())
}

impl AuthService {
    async fn create_subject(&self, subject_type: SubjectType) -> Result<Thing> {
        let now = Utc::now().timestamp();
        let subject_id = Thing::new("subject", Uuid::new_v4().to_string());
        let subject = Subject {
            id: Some(subject_id.clone()),
            subject_type: subject_type.as_str().to_string(),
            created_at: now,
            updated_at: now,
        };

        self.db.create_record("subject", &subject).await?;
        Ok(subject_id)
    }

    async fn ensure_user_subject(&self, user: User, subject_type: SubjectType) -> Result<User> {
        if user.subject_id.is_some() {
            return Ok(user);
        }

        let subject_id = self.create_subject(subject_type).await?;
        let mut updated_user = user.clone();
        updated_user.subject_id = Some(subject_id);
        updated_user.updated_at = Utc::now().timestamp();

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?;
        self.db
            .update_record(
                "user",
                &format!(
                    "{}:{}",
                    user_thing.table,
                    crate::utils::record_id::record_id_key_to_string(user_thing)
                ),
                &updated_user,
            )
            .await
    }

    fn normalize_username(username: &str) -> String {
        username.trim().to_ascii_lowercase()
    }

    async fn ensure_username_available(&self, username: &str) -> Result<String> {
        let normalized = Self::normalize_username(username);
        if normalized.is_empty() {
            return Err(AuthError::ValidationError("Username is required".to_string()));
        }

        if self
            .db
            .find_record_by_field::<User>("user", "username_normalized", &normalized)
            .await?
            .is_some()
        {
            return Err(AuthError::UsernameExists);
        }

        Ok(normalized)
    }

    async fn generate_unique_username(&self, base: &str) -> Result<(String, String)> {
        let fallback = "user";
        let seed = base.trim();
        let seed = if seed.is_empty() { fallback } else { seed };
        let seed = seed
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
            .collect::<String>();
        let seed = if seed.is_empty() {
            fallback.to_string()
        } else {
            seed
        };

        for attempt in 0..1000 {
            let candidate = if attempt == 0 {
                seed.clone()
            } else {
                format!("{seed}{attempt}")
            };
            let normalized = Self::normalize_username(&candidate);
            if self
                .db
                .find_record_by_field::<User>("user", "username_normalized", &normalized)
                .await?
                .is_none()
            {
                return Ok((candidate, normalized));
            }
        }

        Err(AuthError::ServerError(
            "Failed to generate a unique username".to_string(),
        ))
    }

    pub fn new(db: Arc<Database>, config: Config) -> Result<Self> {
        let email_service = EmailService::new(config.clone());
        let oauth_service = OAuthService::new(config.clone())?;
        Ok(Self {
            db,
            config,
            email_service,
            oauth_service,
        })
    }

    pub fn get_google_auth_url(&self) -> Result<String> {
        self.oauth_service.get_google_auth_url()
    }

    pub async fn handle_google_callback(&self, code: String) -> Result<AuthResponse> {
        debug!("Starting Google OAuth callback process");
        
        let user_info = self.oauth_service.handle_google_callback(code).await?;
        debug!("Received user info from Google: {:?}", user_info);

        let user = self.find_or_create_oauth_user(user_info).await?;
        debug!("User found or created: {:?}", user);

        let token = self
            .create_token(&crate::utils::record_id::record_id_key_to_string(
                user.id.as_ref().ok_or(AuthError::UserNotFound)?,
            ))
            .await?;
        debug!("JWT token created successfully");

        debug!("Creating auth response");
        Ok(AuthResponse {
            token,
            user: user.into(),
        })
    }

    pub fn get_github_auth_url(&self) -> Result<String> {
        self.oauth_service.get_github_auth_url()
    }

    pub async fn handle_github_callback(&self, code: String) -> Result<AuthResponse> {
        // 获取 GitHub 用户信息
        let user_info = self.oauth_service.handle_github_callback(code).await?;
        
        // 查找或创建用户
        let user = self.find_or_create_oauth_user(user_info).await?;
        
        // 创建会话
        self.create_session(user).await
    }

    async fn find_or_create_oauth_user(&self, user_info: OAuthUserInfo) -> Result<User> {
        debug!("Starting find_or_create_oauth_user for provider: {} and user_id: {}", 
            user_info.provider, user_info.provider_user_id);

        // 首先通过 identity_provider 查找用户
        debug!("Checking for existing identity provider record");
        if let Some(identity) = self.db.find_record_by_field::<IdentityProvider>(
            "identity_provider",
            "provider_user_id",
            &user_info.provider_user_id,
        ).await?
        {
            debug!("Found existing identity provider record: {:?}", identity);
            // 如果找到身份提供商记录，返回对应的用户
            let user = self.db.find_record_by_field::<User>(
                "user",
                "id",
                &crate::utils::record_id::record_id_key_to_string(&identity.user_id),
            ).await?
            .ok_or(AuthError::UserNotFound)?;
            return self.ensure_user_subject(user, SubjectType::Human).await;
        }

        debug!("No existing identity provider record found");

        // 检查邮箱是否已存在
        debug!("Checking for existing user with email: {}", user_info.email);
        if let Some(existing_user) = self.db.find_record_by_field::<User>(
            "user",
            "email",
            &user_info.email,
        ).await?
        {
            debug!("Found existing user: {:?}", existing_user);
            // 如果找到用户，创建身份提供商记录
            let now = Utc::now();
            let now_ts = now.timestamp();
            let provider_id = new_thing("identity_provider");
            let identity = IdentityProvider {
                id: provider_id.clone(),
                provider: user_info.provider,
                provider_user_id: user_info.provider_user_id,
                user_id: existing_user.id.as_ref().unwrap().clone(),
                created_at: now_ts,
                updated_at: now_ts,
            };
            debug!("Creating identity provider record: {:?}", identity);
            self.db.create_record("identity_provider", &identity).await?;
            debug!("Identity provider record created successfully");
            return self.ensure_user_subject(existing_user, SubjectType::Human).await;
        }

        debug!("No existing user found, creating new user");
        // 创建新用户
        let now = Utc::now();
        let id = new_thing("user");
        let subject_id = self.create_subject(SubjectType::Human).await?;
        let (username, username_normalized) = self
            .generate_unique_username(user_info.email.split('@').next().unwrap_or("user"))
            .await?;
        debug!("Generated new user ID: {:?}", id);
        let user = User {
            id: Some(id.clone()),
            subject_id: Some(subject_id),
            email: user_info.email,
            username,
            username_normalized,
            password_hash: None, // OAuth 用户没有密码
            created_at: now.timestamp(),
            updated_at: now.timestamp(),
            is_email_verified: true, // OAuth 邮箱已验证
            verification_token: None,
            account_status: crate::models::user::AccountStatus::Active.to_string(),
            last_login_at: Some(now.timestamp()),
            last_login_ip: Some("0.0.0.0".to_string()),
        };

        debug!("Creating new user record: {:?}", user);
        let created_user = self.db.create_record("user", &user).await?;
        debug!("User created successfully: {:?}", created_user);

        // 创建身份提供商记录
        let now = Utc::now();
        let now_ts = now.timestamp();
        let provider_id = new_thing("identity_provider");
        let identity = IdentityProvider {
            id: provider_id.clone(),
            provider: user_info.provider,
            provider_user_id: user_info.provider_user_id,
            user_id: id.clone(),
            created_at: now_ts,
            updated_at: now_ts,
        };
        debug!("Creating identity provider record: {:?}", identity);
        self.db.create_record("identity_provider", &identity).await?;
        debug!("Identity provider record created successfully");

        Ok(created_user)
    }

    pub async fn register(&self, req: CreateUserRequest) -> Result<AuthResponse> {
        // 检查邮箱是否已存在
        if let Some(_) = self.db.find_record_by_field::<User>(
            "user",
            "email",
            &req.email,
        ).await?
        {
            return Err(AuthError::EmailExists);
        }

        let username = req
            .username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthError::ValidationError("Username is required".to_string()))?
            .to_string();
        let username_normalized = self.ensure_username_available(&username).await?;

        // 生成密码哈希
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hashed_password = argon2
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|e| AuthError::ServerError(e.to_string()))?
            .to_string();

        // 创建用户
        let now = Utc::now();
        let verification_token = if self.config.email_verification_enabled {
            Some(Uuid::new_v4().to_string())
        } else {
            None
        };
        let id = new_thing("user");
        let subject_id = self.create_subject(SubjectType::Human).await?;
        let user = User {
            id: Some(id),
            subject_id: Some(subject_id),
            email: req.email.clone(),
            username,
            username_normalized,
            password_hash: Some(hashed_password),
            created_at: now.timestamp(),
            updated_at: now.timestamp(),
            is_email_verified: !self.config.email_verification_enabled,
            verification_token: verification_token.clone(),
            account_status: crate::models::user::AccountStatus::Active.to_string(),
            last_login_at: Some(now.timestamp()),
            last_login_ip: None,
        };

        let created_user = self.db.create_record("user", &user).await?;

        if self.config.email_verification_enabled {
            if let Some(token) = verification_token {
                self.email_service.send_verification_email(&req.email, &token).await?;
            }

            Ok(AuthResponse {
                token: "".to_string(),
                user: created_user.into(),
            })
        } else {
            self.create_session(created_user).await
        }
    }

    pub async fn login(&self, email: String, password: String) -> Result<AuthResponse> {
        // 查找用户
        let mut user = self.db.find_record_by_field::<User>(
            "user",
            "email",
            &email,
        ).await?
        .ok_or(AuthError::InvalidCredentials)?;

        // 验证密码
        let password_hash = user.password_hash
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| AuthError::ServerError(e.to_string()))?;
        
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        // 检查邮箱验证状态
        if self.config.email_verification_enabled && !user.is_email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        // 检查账户状态
        match user.account_status.as_str() {
            "Suspended" => return Err(AuthError::AccountSuspended),
            "Inactive" => return Err(AuthError::AccountInactive),
            "PendingDeletion" | "Deleted" => return Err(AuthError::AccountDeleted),
            _ => {}
        }

        // 更新最后登录信息
        let now = Utc::now();
        user = self.ensure_user_subject(user, SubjectType::Human).await?;
        user.last_login_at = Some(now.timestamp());
        user.last_login_ip = Some("0.0.0.0".to_string()); // 这里应该从请求中获取真实IP
        user.updated_at = now.timestamp();

        // 更新用户记录
        let user_thing = user.id.as_ref().unwrap();
        let updated_user = self
            .db
            .update_record(
                "user",
                &format!(
                    "{}:{}",
                    user_thing.table,
                    crate::utils::record_id::record_id_key_to_string(user_thing)
                ),
                &user,
            )
            .await?;

        // 创建会话
        self.create_session(updated_user).await
    }

    async fn create_session(&self, user: User) -> Result<AuthResponse> {
        self.create_session_with_metadata(user, "Unknown".to_string(), "0.0.0.0".to_string()).await
    }

    async fn create_session_with_metadata(&self, user: User, user_agent: String, ip_address: String) -> Result<AuthResponse> {
        let now = Utc::now();
        let exp = now + Duration::hours(24); // 24小时后过期

        // 创建会话记录
        let session_id = new_thing("session");

        let session = Session {
            id: Some(session_id.clone()),
            user_id: user.id.as_ref().unwrap().clone(),
            token: "".to_string(), // 临时空值，稍后更新
            expires_at: exp.timestamp(),
            created_at: now.timestamp(),
            user_agent,
            ip_address,
        };

        // 创建JWT claims，包含session_id
        let claims = Claims {
            sub: crate::utils::record_id::record_id_key_to_string(user.id.as_ref().unwrap()),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            session_id: Some(crate::utils::record_id::record_id_key_to_string(&session_id)),
            subject_type: Some(SubjectType::Human),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::TokenError(e.to_string()))?;

        // 更新会话记录的token
        let mut session_with_token = session;
        session_with_token.token = token.clone();

        // 保存会话到数据库
        self.db.create_record("session", &session_with_token).await?;

        Ok(AuthResponse {
            token,
            user: user.into(),
        })
    }

    async fn create_token(&self, user_id: &str) -> Result<String> {
        debug!("Starting token creation for user ID: {}", user_id);
        let now = Utc::now();
        let exp = now + Duration::hours(24); // 24小时后过期

        // 创建会话记录
        let session_id = new_thing("session");

        let user_thing: Thing = if let Some((tb, key_raw)) = user_id.split_once(':') {
            Thing::new(tb, key_raw.trim().trim_matches('⟨').trim_matches('⟩'))
        } else {
            Thing::new("user", user_id.to_string())
        };

        let session = Session {
            id: Some(session_id.clone()),
            user_id: user_thing,
            token: "".to_string(), // 临时空值，稍后更新
            expires_at: exp.timestamp(),
            created_at: now.timestamp(),
            user_agent: "OAuth".to_string(),
            ip_address: "0.0.0.0".to_string(),
        };

        let claims = Claims {
            sub: user_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            session_id: Some(crate::utils::record_id::record_id_key_to_string(&session_id)),
            subject_type: Some(SubjectType::Human),
        };
        debug!("Created JWT claims: {:?}", claims);

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| {
            error!("Failed to create JWT token: {}", e);
            AuthError::TokenError(e.to_string())
        })?;

        // 更新会话记录的token
        let mut session_with_token = session;
        session_with_token.token = token.clone();

        // 保存会话到数据库
        self.db.create_record("session", &session_with_token).await?;
        debug!("JWT token created successfully");

        Ok(token)
    }

    pub async fn verify_email(&self, token: String) -> Result<AuthResponse> {
        let user = self.db.find_record_by_field::<User>(
            "user",
            "verification_token",
            &token,
        ).await?
        .ok_or(AuthError::InvalidToken)?;

        // 检查用户是否已经验证
        if user.is_email_verified {
            return Err(AuthError::InvalidToken);
        }

        let mut updated_user = user.clone();
        updated_user.is_email_verified = true;
        updated_user.verification_token = None;
        updated_user.updated_at = Utc::now().timestamp();
        updated_user.id = user.id.clone();

        let user_thing = user.id.as_ref().unwrap();
        let verified_user = self
            .db
            .update_record(
                "user",
                &format!(
                    "{}:{}",
                    user_thing.table,
                    crate::utils::record_id::record_id_key_to_string(user_thing)
                ),
                &updated_user,
            )
            .await?;

        // 验证成功后创建会话
        self.create_session(verified_user).await
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>> {
        self.db.find_record_by_field("user", "id", user_id).await
    }

    pub async fn get_user_by_subject_id(&self, subject_id: &str) -> Result<Option<User>> {
        let query = "SELECT * FROM user WHERE subject_id = type::thing($subject_id) LIMIT 1";
        let mut result = self
            .db
            .query(query)
            .bind(("subject_id", subject_id.to_string()))
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to query user by subject_id: {}", e)))?;

        let users: Vec<User> = result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse user by subject_id: {}", e)))?;

        Ok(users.into_iter().next())
    }

    pub async fn resolve_authenticated_user(&self, claims: &crate::utils::jwt::Claims) -> Result<User> {
        if claims.sub.starts_with("subject:") {
            self.get_user_by_subject_id(&claims.sub)
                .await?
                .ok_or(AuthError::UserNotFound)
        } else {
            self.get_user_by_id(&claims.sub)
                .await?
                .ok_or(AuthError::UserNotFound)
        }
    }

    pub async fn resolve_authenticated_user_id(&self, claims: &crate::utils::jwt::Claims) -> Result<String> {
        let user = self.resolve_authenticated_user(claims).await?;
        let user_id = user.id.as_ref().ok_or(AuthError::UserNotFound)?;
        Ok(crate::utils::record_id::record_id_key_to_string(user_id))
    }

    pub async fn initialize_password(&self, user_id: &str, password: &str) -> Result<User> {
        let thing: Thing = if let Some((tb, key_raw)) = user_id.split_once(':') {
            Thing::new(tb, key_raw.trim().trim_matches('⟨').trim_matches('⟩'))
        } else {
            Thing::new("user", user_id.to_string())
        };

        let mut user: User = self.db.find_record_by_field("user", "id", user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // 如果用户已经有密码，返回错误
        if user.password_hash.is_some() {
            return Err(AuthError::PasswordAlreadySet);
        }

        // 设置密码
        user.password_hash = Some(hash_password(password)?);
        user.updated_at = Utc::now().timestamp();

        // 更新用户记录
        self.db
            .update_record(
                "user",
                &format!(
                    "{}:{}",
                    thing.table,
                    crate::utils::record_id::record_id_key_to_string(&thing)
                ),
                &user,
            )
            .await
    }

    pub async fn request_password_reset(&self, email: String) -> Result<()> {
        // 检查用户是否存在
        let user = self.db.find_record_by_field::<User>(
            "user",
            "email",
            &email,
        ).await?;

        if user.is_none() {
            // 即使用户不存在，也要返回成功，以防止邮箱枚举攻击
            return Ok(());
        }

        // 生成重置令牌
        let reset_token = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::hours(1); // 1小时后过期

        let id = new_thing("password_reset_token");

        let token_record = PasswordResetToken {
            id: Some(id),
            email: email.clone(),
            token: reset_token.clone(),
            expires_at,
            used: false,
            created_at: now,
        };

        // 保存重置令牌
        self.db.create_record("password_reset_token", &token_record).await?;

        // 发送重置邮件
        self.email_service.send_password_reset_email(&email, &reset_token).await?;

        Ok(())
    }

    pub async fn reset_password(&self, token: String, new_password: String) -> Result<()> {
        // 查找重置令牌
        let reset_token = self.db.find_record_by_field::<PasswordResetToken>(
            "password_reset_token",
            "token",
            &token,
        ).await?
        .ok_or(AuthError::InvalidToken)?;

        // 检查令牌是否已使用
        if reset_token.used {
            return Err(AuthError::InvalidToken);
        }

        // 检查令牌是否过期
        if reset_token.expires_at < Utc::now() {
            return Err(AuthError::InvalidToken);
        }

        // 查找用户
        let mut user = self.db.find_record_by_field::<User>(
            "user",
            "email",
            &reset_token.email,
        ).await?
        .ok_or(AuthError::UserNotFound)?;

        // 更新密码
        user.password_hash = Some(hash_password(&new_password)?);
        user.updated_at = Utc::now().timestamp();

        // 更新用户记录
        let user_thing = user.id.as_ref().unwrap();
        self.db
            .update_record(
                "user",
                &format!(
                    "{}:{}",
                    user_thing.table,
                    crate::utils::record_id::record_id_key_to_string(user_thing)
                ),
                &user,
            )
            .await?;

        // 标记令牌为已使用
        let mut updated_token = reset_token.clone();
        updated_token.used = true;
        let token_thing = reset_token.id.as_ref().unwrap();
        self.db
            .update_record(
                "password_reset_token",
                &format!(
                    "{}:{}",
                    token_thing.table,
                    crate::utils::record_id::record_id_key_to_string(token_thing)
                ),
                &updated_token,
            )
            .await?;

        Ok(())
    }

    pub async fn logout(&self, token: String) -> Result<()> {
        // 删除会话记录
        self.db.delete_session_by_token(&token).await?;
        Ok(())
    }

    pub async fn logout_all_sessions(&self, user_id: &str) -> Result<()> {
        // 删除用户的所有会话
        self.db.delete_sessions_by_user_id(user_id).await?;
        Ok(())
    }

    pub async fn get_user_sessions(&self, user_id: &str, current_token: &str) -> Result<Vec<SessionInfo>> {
        let sessions = self.db.get_sessions_by_user_id(user_id).await?;
        
        let session_infos: Vec<SessionInfo> = sessions
            .into_iter()
            .map(|session| SessionInfo {
                id: crate::utils::record_id::record_id_key_to_string(session.id.as_ref().unwrap()),
                created_at: DateTime::<Utc>::from_timestamp(session.created_at, 0)
                    .unwrap_or_else(|| Utc::now()),
                user_agent: session.user_agent,
                ip_address: session.ip_address,
                is_current: session.token == current_token,
            })
            .collect();

        Ok(session_infos)
    }
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hashed_password = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::ServerError(e.to_string()))?
        .to_string();
    Ok(hashed_password)
}
