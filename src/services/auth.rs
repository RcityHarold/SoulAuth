use crate::{
    config::Config,
    error::{AuthError, Result},
    models::{
        identity_provider::{IdentityProvider, OAuthUserInfo},
        mfa::MfaMethod,
        password_reset::PasswordResetToken,
        session::{Session, SessionInfo},
        subject::{Subject, SubjectType},
        user::{AuthResponse, CreateUserRequest, User},
    },
    services::{
        auth_cache::AuthCache, database::Database, email::EmailService, mfa::MfaService,
        oauth::OAuthService,
    },
    utils::validation::{validate_email, validate_password, validate_username},
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use surrealdb::types::RecordId as Thing;
use tracing::{debug, error, info};
use uuid::Uuid;

/// 邮箱验证令牌有效期。
const VERIFICATION_TOKEN_TTL_HOURS: i64 = 24;
/// 会话（以及随之签发的访问令牌）有效期。
const SESSION_TTL_HOURS: i64 = 24;

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

/// 请求上下文：真实来源 IP 与 User-Agent。
///
/// 以前这两个值在会话与登录记录里被硬编码成 `"0.0.0.0"` / `"Unknown"`，
/// 导致会话列表和审计报表里的数据全是假的。
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub ip_address: String,
    pub user_agent: String,
}

impl RequestContext {
    pub fn new(ip_address: String, user_agent: String) -> Self {
        Self {
            ip_address,
            user_agent,
        }
    }

}

/// 一次成功签发的会话。
///
/// `session_key` 是 `session` 表记录的主键，用来把浏览器会话 cookie 绑到具体
/// 会话行上 —— 否则那个 cookie 是个自包含 JWT，登出之后照样能在
/// `/api/oidc/authorize` 换到授权码。
pub struct IssuedSession {
    pub response: AuthResponse,
    pub session_key: String,
}

/// 登录结果：直接放行，或要求补一步 MFA。
pub enum LoginOutcome {
    Authenticated(Box<IssuedSession>),
    MfaRequired {
        temp_token: String,
        method: MfaMethod,
    },
}

pub struct AuthService {
    db: Arc<Database>,
    config: Config,
    email_service: EmailService,
    oauth_service: OAuthService,
    mfa_service: MfaService,
    /// 用于在会话被吊销时立刻同步清掉鉴权缓存。
    auth_cache: Arc<AuthCache>,
}

fn new_thing(table: &str) -> Thing {
    Thing::new(table, Uuid::new_v4().to_string())
}

fn record_key(thing: &Thing) -> String {
    crate::utils::record_id::record_id_key_to_string(thing)
}

fn record_address(thing: &Thing) -> String {
    format!("{}:{}", thing.table, record_key(thing))
}

impl AuthService {
    pub fn new(db: Arc<Database>, config: Config, auth_cache: Arc<AuthCache>) -> Result<Self> {
        // 在启动阶段就把哑哈希算出来。留给第一个请求懒初始化的话，进程起来后
        // 第一次"邮箱不存在"的登录要额外背一次 Argon2 哈希（实测约 350ms），
        // 恰好是这个哑哈希本该消除的那种耗时差异 —— 方向相反、只发生一次，
        // 但没必要留着。这里多花的启动时间发生在监听端口之前。
        let _ = dummy_password_hash();

        let email_service = EmailService::new(config.clone());
        let oauth_service = OAuthService::new(config.clone())?;
        let mfa_service = MfaService::new(db.clone(), config.clone())?;
        Ok(Self {
            db,
            config,
            email_service,
            oauth_service,
            mfa_service,
            auth_cache,
        })
    }

    pub fn mfa(&self) -> &MfaService {
        &self.mfa_service
    }

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
            .update_record("user", &record_address(user_thing), &updated_user)
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
        let mut seed = if seed.is_empty() {
            fallback.to_string()
        } else {
            seed
        };
        // 用户名有最短长度要求，OAuth 昵称过短时补齐。
        while seed.len() < 3 {
            seed.push('0');
        }

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

    pub fn get_google_auth_url_with_state(&self, state: &str) -> Result<String> {
        self.oauth_service.get_google_auth_url_with_state(state)
    }

    pub fn get_github_auth_url_with_state(&self, state: &str) -> Result<String> {
        self.oauth_service.get_github_auth_url_with_state(state)
    }

    pub async fn handle_google_callback(
        &self,
        code: String,
        ctx: &RequestContext,
    ) -> Result<IssuedSession> {
        debug!("Starting Google OAuth callback process");

        let user_info = self.oauth_service.handle_google_callback(code).await?;
        let user = self.find_or_create_oauth_user(user_info).await?;
        let user = self.touch_last_login(user, ctx).await?;

        self.create_session_with_metadata(user, ctx).await
    }

    pub async fn handle_github_callback(
        &self,
        code: String,
        ctx: &RequestContext,
    ) -> Result<IssuedSession> {
        let user_info = self.oauth_service.handle_github_callback(code).await?;
        let user = self.find_or_create_oauth_user(user_info).await?;
        let user = self.touch_last_login(user, ctx).await?;

        self.create_session_with_metadata(user, ctx).await
    }

    async fn find_or_create_oauth_user(&self, user_info: OAuthUserInfo) -> Result<User> {
        debug!(
            "Starting find_or_create_oauth_user for provider: {}",
            user_info.provider
        );

        // 首先通过 identity_provider 查找用户
        if let Some(identity) = self
            .db
            .find_record_by_field::<IdentityProvider>(
                "identity_provider",
                "provider_user_id",
                &user_info.provider_user_id,
            )
            .await?
        {
            let user = self
                .db
                .find_record_by_field::<User>("user", "id", &record_key(&identity.user_id))
                .await?
                .ok_or(AuthError::UserNotFound)?;
            return self.ensure_user_subject(user, SubjectType::Human).await;
        }

        let email = validate_email(&user_info.email)?;

        // 邮箱已存在则把该身份源挂到既有账号上
        if let Some(existing_user) = self
            .db
            .find_record_by_field::<User>("user", "email", &email)
            .await?
        {
            let now_ts = Utc::now().timestamp();
            let identity = IdentityProvider {
                id: new_thing("identity_provider"),
                provider: user_info.provider,
                provider_user_id: user_info.provider_user_id,
                user_id: existing_user
                    .id
                    .as_ref()
                    .ok_or(AuthError::UserNotFound)?
                    .clone(),
                created_at: now_ts,
                updated_at: now_ts,
            };
            self.db.create_record("identity_provider", &identity).await?;
            return self.ensure_user_subject(existing_user, SubjectType::Human).await;
        }

        // 创建新用户
        let now = Utc::now();
        let id = new_thing("user");
        let subject_id = self.create_subject(SubjectType::Human).await?;
        let (username, username_normalized) = self
            .generate_unique_username(email.split('@').next().unwrap_or("user"))
            .await?;
        let user = User {
            id: Some(id.clone()),
            subject_id: Some(subject_id),
            email,
            username,
            username_normalized,
            password_hash: None, // OAuth 用户没有密码
            created_at: now.timestamp(),
            updated_at: now.timestamp(),
            is_email_verified: true, // OAuth 邮箱已验证
            verification_token: None,
            verification_token_expires_at: None,
            account_status: crate::models::user::AccountStatus::Active.to_string(),
            membership_level: "FREE".to_string(),
            membership_expiry: None,
            last_login_at: None,
            last_login_ip: None,
        };

        let created_user = self.db.create_record("user", &user).await?;

        let now_ts = Utc::now().timestamp();
        let identity = IdentityProvider {
            id: new_thing("identity_provider"),
            provider: user_info.provider,
            provider_user_id: user_info.provider_user_id,
            user_id: id,
            created_at: now_ts,
            updated_at: now_ts,
        };
        self.db.create_record("identity_provider", &identity).await?;

        Ok(created_user)
    }

    pub async fn register(
        &self,
        req: CreateUserRequest,
        ctx: &RequestContext,
    ) -> Result<(AuthResponse, Option<String>)> {
        let email = validate_email(&req.email)?;
        validate_password(&req.password, self.config.password_min_length)?;

        let username = validate_username(
            req.username
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| AuthError::ValidationError("Username is required".to_string()))?,
        )?;

        if self
            .db
            .find_record_by_field::<User>("user", "email", &email)
            .await?
            .is_some()
        {
            return Err(AuthError::EmailExists);
        }

        let username_normalized = self.ensure_username_available(&username).await?;
        let hashed_password = hash_password_blocking(req.password.clone()).await?;

        let now = Utc::now();
        let (verification_token, verification_expires_at) = if self.config.email_verification_enabled
        {
            (
                Some(Uuid::new_v4().to_string()),
                Some((now + Duration::hours(VERIFICATION_TOKEN_TTL_HOURS)).timestamp()),
            )
        } else {
            (None, None)
        };

        let user = User {
            id: Some(new_thing("user")),
            subject_id: Some(self.create_subject(SubjectType::Human).await?),
            email: email.clone(),
            username,
            username_normalized,
            password_hash: Some(hashed_password),
            created_at: now.timestamp(),
            updated_at: now.timestamp(),
            is_email_verified: !self.config.email_verification_enabled,
            verification_token: verification_token.clone(),
            verification_token_expires_at: verification_expires_at,
            account_status: crate::models::user::AccountStatus::Active.to_string(),
            membership_level: "FREE".to_string(),
            membership_expiry: None,
            last_login_at: None,
            last_login_ip: None,
        };

        let created_user = self.db.create_record("user", &user).await?;

        if let Some(token) = verification_token {
            // 用户记录已经提交了，此时再抛错只会让调用方拿到 500、重试又撞 409，
            // 账号就永远卡在“已创建但没收到验证信”。发信失败只记日志。
            if let Err(e) = self
                .email_service
                .send_verification_email(&email, &token)
                .await
            {
                error!("Failed to send verification email to '{email}': {e}");
            }

            return Ok((
                AuthResponse {
                    token: String::new(),
                    user: created_user.into(),
                },
                None,
            ));
        }

        let created_user = self.touch_last_login(created_user, ctx).await?;
        let issued = self.create_session_with_metadata(created_user, ctx).await?;
        Ok((issued.response, Some(issued.session_key)))
    }

    pub async fn login(
        &self,
        email: String,
        password: String,
        ctx: &RequestContext,
    ) -> Result<LoginOutcome> {
        let email = validate_email(&email).map_err(|_| AuthError::InvalidCredentials)?;

        let user = match self
            .db
            .find_record_by_field::<User>("user", "email", &email)
            .await?
        {
            Some(user) => user,
            None => {
                // 邮箱没注册过也要把 Argon2 的时间花掉，否则响应快得多，
                // 等于告诉调用方"这个邮箱不存在"。
                spend_password_verification_time().await;
                return Err(AuthError::InvalidCredentials);
            }
        };

        // 验证密码
        let password_hash = match user.password_hash.clone() {
            Some(hash) => hash,
            None => {
                // 纯 OAuth 账号没有密码哈希，同理不能提前返回。
                spend_password_verification_time().await;
                return Err(AuthError::InvalidCredentials);
            }
        };

        verify_password_blocking(password_hash, password).await?;

        // 检查邮箱验证状态
        if self.config.email_verification_enabled && !user.is_email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        // 检查账户状态
        Self::ensure_account_usable(&user)?;

        let user = self.ensure_user_subject(user, SubjectType::Human).await?;
        let user_id = record_key(user.id.as_ref().ok_or(AuthError::UserNotFound)?);

        // 启用了 MFA 的账号在这里止步，只发一个 5 分钟有效的挑战令牌。
        if let Some(method) = self.mfa_service.enabled_method(&user_id).await? {
            let temp_token = crate::utils::jwt::create_mfa_challenge_token(
                &user_id,
                &user.email,
                &self.config.jwt_secret,
            )?;
            return Ok(LoginOutcome::MfaRequired { temp_token, method });
        }

        let user = self.touch_last_login(user, ctx).await?;
        let response = self.create_session_with_metadata(user, ctx).await?;
        Ok(LoginOutcome::Authenticated(Box::new(response)))
    }

    /// MFA 第二步通过之后完成登录。
    pub async fn complete_mfa_login(
        &self,
        user_id: &str,
        ctx: &RequestContext,
    ) -> Result<IssuedSession> {
        let user = self
            .db
            .find_record_by_field::<User>("user", "id", user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        Self::ensure_account_usable(&user)?;

        let user = self.touch_last_login(user, ctx).await?;
        self.create_session_with_metadata(user, ctx).await
    }

    /// 登录闸门。与 `utils::jwt` 的令牌闸门共用同一份状态判定
    /// （`AccountStatus::parse`），两处以前是逐字副本，谁也拦不住它们走偏。
    fn ensure_account_usable(user: &User) -> Result<()> {
        use crate::models::user::AccountStatus;
        match user.account_status_parsed() {
            AccountStatus::Active => Ok(()),
            AccountStatus::Suspended => Err(AuthError::AccountSuspended),
            AccountStatus::Inactive => Err(AuthError::AccountInactive),
            AccountStatus::PendingDeletion | AccountStatus::Deleted => {
                Err(AuthError::AccountDeleted)
            }
        }
    }

    async fn touch_last_login(&self, mut user: User, ctx: &RequestContext) -> Result<User> {
        let now = Utc::now().timestamp();
        user.last_login_at = Some(now);
        user.last_login_ip = Some(ctx.ip_address.clone());
        user.updated_at = now;

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?.clone();
        self.db
            .update_record("user", &record_address(&user_thing), &user)
            .await
    }

    async fn create_session_with_metadata(
        &self,
        user: User,
        ctx: &RequestContext,
    ) -> Result<IssuedSession> {
        let now = Utc::now();
        let exp = now + Duration::hours(SESSION_TTL_HOURS);

        let session_id = new_thing("session");
        let session_key = record_key(&session_id);
        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?.clone();

        let claims = Claims {
            sub: record_key(&user_thing),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            session_id: Some(session_key.clone()),
            subject_type: Some(SubjectType::Human),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::TokenError(e.to_string()))?;

        let session = Session {
            id: Some(session_id),
            user_id: user_thing,
            token: token.clone(),
            expires_at: exp.timestamp(),
            created_at: now.timestamp(),
            user_agent: ctx.user_agent.clone(),
            ip_address: ctx.ip_address.clone(),
        };

        self.db.create_record("session", &session).await?;

        Ok(IssuedSession {
            response: AuthResponse {
                token,
                user: user.into(),
            },
            session_key,
        })
    }

    pub async fn verify_email(&self, token: String, ctx: &RequestContext) -> Result<IssuedSession> {
        let user = self
            .db
            .find_record_by_field::<User>("user", "verification_token", &token)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if user.is_email_verified {
            return Err(AuthError::InvalidToken);
        }

        // 验证令牌以前永不过期，现在超时即作废。
        if let Some(expires_at) = user.verification_token_expires_at {
            if expires_at < Utc::now().timestamp() {
                return Err(AuthError::InvalidToken);
            }
        }

        let mut updated_user = user.clone();
        updated_user.is_email_verified = true;
        updated_user.verification_token = None;
        updated_user.verification_token_expires_at = None;
        updated_user.updated_at = Utc::now().timestamp();

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?;
        let verified_user = self
            .db
            .update_record("user", &record_address(user_thing), &updated_user)
            .await?;

        let verified_user = self.touch_last_login(verified_user, ctx).await?;
        self.create_session_with_metadata(verified_user, ctx).await
    }

    pub async fn initialize_password(&self, user_id: &str, password: &str) -> Result<User> {
        validate_password(password, self.config.password_min_length)?;

        let mut user: User = self
            .db
            .find_record_by_field("user", "id", user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        if user.password_hash.is_some() {
            return Err(AuthError::PasswordAlreadySet);
        }

        user.password_hash = Some(hash_password_blocking(password.to_string()).await?);
        user.updated_at = Utc::now().timestamp();

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?.clone();
        self.db
            .update_record("user", &record_address(&user_thing), &user)
            .await
    }

    pub async fn request_password_reset(&self, email: String) -> Result<()> {
        // 邮箱不合法或用户不存在都静默返回成功，避免暴露账号是否存在。
        let email = match validate_email(&email) {
            Ok(email) => email,
            Err(_) => return Ok(()),
        };

        let user = self
            .db
            .find_record_by_field::<User>("user", "email", &email)
            .await?;

        if user.is_none() {
            return Ok(());
        }

        // 先作废该邮箱名下所有还没用掉的旧令牌，保证任一时刻只有最新那封邮件有效。
        // 否则每点一次"忘记密码"就多留一把可用的钥匙，全都活到各自的 1 小时到期为止。
        self.invalidate_password_reset_tokens(&email).await?;

        let reset_token = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::hours(1);

        let token_record = PasswordResetToken {
            id: Some(new_thing("password_reset_token")),
            email: email.clone(),
            token: reset_token.clone(),
            expires_at,
            used: false,
            created_at: now,
        };

        self.db
            .create_record("password_reset_token", &token_record)
            .await?;

        // 发信失败不能往外抛。未知邮箱这条路径直接 `Ok(())`，若已知邮箱因 SMTP 挂了
        // 而返回 500，两者的差异就成了账号是否存在的判别信号 —— 上面那段防枚举的
        // 静默返回等于白做。SMTP 抖动也不该让用户流程断掉，令牌已经落库了。
        if let Err(e) = self
            .email_service
            .send_password_reset_email(&email, &reset_token)
            .await
        {
            error!("Failed to send password reset email: {e}");
        }

        Ok(())
    }

    /// 把某邮箱名下所有未使用的重置令牌标记为已用。
    ///
    /// 签发新令牌前、以及某个令牌被成功兑换后都要调用：这两条路径都必须让此前
    /// 发出去的链接立刻失效，否则攻击者事先触发的那封重置邮件在受害者改完密码
    /// 之后仍然能用来再改一次。
    async fn invalidate_password_reset_tokens(&self, email: &str) -> Result<()> {
        self.db
            .raw_query(
                "invalidate_password_reset_tokens",
                "UPDATE password_reset_token SET used = true WHERE email = $email AND used = false",
                serde_json::json!({ "email": email }),
            )
            .await?;
        Ok(())
    }

    /// 重置密码，返回受影响的用户 ID（供审计埋点使用）。
    pub async fn reset_password(&self, token: String, new_password: String) -> Result<String> {
        validate_password(&new_password, self.config.password_min_length)?;

        let reset_token = self
            .db
            .find_record_by_field::<PasswordResetToken>("password_reset_token", "token", &token)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if reset_token.used || reset_token.expires_at < Utc::now() {
            return Err(AuthError::InvalidToken);
        }

        let mut user = self
            .db
            .find_record_by_field::<User>("user", "email", &reset_token.email)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        user.password_hash = Some(hash_password_blocking(new_password.clone()).await?);
        user.updated_at = Utc::now().timestamp();

        let user_thing = user.id.as_ref().ok_or(AuthError::UserNotFound)?.clone();
        self.db
            .update_record("user", &record_address(&user_thing), &user)
            .await?;

        let mut updated_token = reset_token.clone();
        updated_token.used = true;
        let token_thing = reset_token.id.as_ref().ok_or(AuthError::InvalidToken)?;
        self.db
            .update_record(
                "password_reset_token",
                &record_address(token_thing),
                &updated_token,
            )
            .await?;

        // 同一邮箱名下可能还有别的未使用令牌（例如攻击者抢先申请、或用户连点了
        // 几次"忘记密码"）。密码既然已经改了，剩下那些一律作废。
        self.invalidate_password_reset_tokens(&reset_token.email)
            .await?;

        // 改密之后强制所有既有会话下线。
        let user_id = record_key(&user_thing);
        if let Err(e) = self.db.delete_sessions_by_user_id(&user_id).await {
            error!("Failed to revoke sessions after password reset: {:?}", e);
        }
        self.auth_cache.invalidate_user(&user_id).await;
        info!("Password reset completed; all sessions revoked");

        Ok(user_id)
    }

    pub async fn logout(&self, token: String) -> Result<()> {
        self.db.delete_session_by_token(&token).await?;
        self.auth_cache.invalidate_token(&token).await;
        Ok(())
    }

    pub async fn logout_all_sessions(&self, user_id: &str) -> Result<()> {
        self.db.delete_sessions_by_user_id(user_id).await?;
        self.auth_cache.invalidate_user(user_id).await;
        Ok(())
    }

    pub async fn get_user_sessions(
        &self,
        user_id: &str,
        current_token: &str,
    ) -> Result<Vec<SessionInfo>> {
        let sessions = self.db.get_sessions_by_user_id(user_id).await?;

        let session_infos: Vec<SessionInfo> = sessions
            .into_iter()
            .filter_map(|session| {
                let id = session.id.as_ref().map(record_key)?;
                Some(SessionInfo {
                    id,
                    created_at: DateTime::<Utc>::from_timestamp(session.created_at, 0)
                        .unwrap_or_else(Utc::now),
                    user_agent: session.user_agent,
                    ip_address: session.ip_address,
                    is_current: session.token == current_token,
                })
            })
            .collect();

        Ok(session_infos)
    }
}

/// 一个固定的、谁也不知道原文的 Argon2 哈希，用来给"账号不存在"这条路径垫上
/// 等量的计算。
///
/// 参数必须和 `hash_password` 一致（都用 `Argon2::default()`），否则耗时对不上，
/// 垫了也白垫。只算一次。
static DUMMY_PASSWORD_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn dummy_password_hash() -> &'static str {
    DUMMY_PASSWORD_HASH.get_or_init(|| {
        // 原文用随机值，保证没人能构造出匹配它的密码。
        let filler = Uuid::new_v4().to_string();
        hash_password(&filler).unwrap_or_default()
    })
}

/// 账号不存在 / 没有密码时，照样跑一次 Argon2 校验再丢掉结果。
///
/// 登录失败的文案两条路径是一样的，但耗时不是：命中账号要跑 Argon2（几十毫秒），
/// 没命中则立刻返回。这个差值在网络上很容易测出来，等于把"这个邮箱注册过没有"
/// 白送出去。这里把两条路径的计算量拉平。
async fn spend_password_verification_time() {
    let _ = verify_password_blocking(dummy_password_hash().to_string(), "invalid-password".into())
        .await;
}

/// Argon2 是几十毫秒的**纯 CPU** 运算，直接在 async fn 里跑会把 tokio 的工作
/// 线程整个占住。核数不多的机器上，几个并发登录就能把可用的工作线程吃光，
/// 连不相干的接口一起变慢。和 SMTP 发送同理，挪到阻塞线程池。
async fn verify_password_blocking(stored_hash: String, password: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&stored_hash)
            .map_err(|e| AuthError::ServerError(e.to_string()))?;
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .map_err(|_| AuthError::InvalidCredentials)
    })
    .await
    .map_err(|e| AuthError::ServerError(format!("Password verification task panicked: {e}")))?
}

/// 同上：哈希一次密码也要几十毫秒，注册 / 改密路径同样不能占着工作线程。
async fn hash_password_blocking(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| AuthError::ServerError(format!("Password hashing task panicked: {e}")))?
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
