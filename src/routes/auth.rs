use crate::{
    config::Config,
    error::{AuthError, Result},
    models::account_lockout::LockoutCheckResult,
    models::user::{CreateUserRequest, LoginRequest, AuthResponse, UserResponse, InitializePasswordRequest},
    models::password_reset::{RequestPasswordResetRequest, ResetPasswordRequest},
    models::session::{LogoutRequest, SessionInfo},
    services::auth::AuthService,
    utils::jwt::Claims,
};
use axum::{
    extract::{Query, State, TypedHeader, ConnectInfo},
    headers::{authorization::Bearer, Authorization},
    routing::{get, post},
    Json, Router,
    Extension,
    response::IntoResponse,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use std::{sync::Arc, net::SocketAddr};
use crate::{services::database::Database, utils::rate_limit_middleware::check_rate_limit_for_request, AppState};
use tracing::{error, info, warn};
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    code: String,
    state: Option<String>,
}

/// 获取客户端IP地址的辅助函数
fn get_client_ip(addr: &SocketAddr, headers: &HeaderMap) -> String {
    // 尝试从头部获取真实IP
    if let Some(forwarded_for) = headers.get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            if let Some(ip) = forwarded_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    if let Some(real_ip) = headers.get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }

    // 回退到连接地址
    addr.ip().to_string()
}

pub fn router(db: Arc<Database>) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/verify-email/:token", get(verify_email))
        .route("/me", get(get_current_user))
        .route("/initialize-password", post(initialize_password))
        .route("/request-password-reset", post(request_password_reset))
        .route("/reset-password", post(reset_password))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/sessions", get(get_sessions))
        // OAuth 路由
        .route("/login/google", get(google_login))
        .route("/callback/google", get(google_callback))
        .route("/login/github", get(github_login))
        .route("/callback/github", get(github_callback))
        .with_state(db)
}

// 注册处理函数
async fn register(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Extension(app_state): Extension<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> std::result::Result<&'static str, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!("Starting user registration");
    
    // 获取客户端IP
    let client_ip = get_client_ip(&addr, &headers);
    
    // 检查速率限制
    check_rate_limit_for_request(&app_state.rate_limiter, &client_ip, "/api/auth/register").await?;
    
    let auth_service = AuthService::new(db, config).map_err(|e| {
        error!("Failed to create auth service: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Internal server error",
            "message": "Service unavailable"
        })))
    })?;
    
    let result = auth_service.register(req).await.map_err(|e| {
        error!("Registration failed: {:?}", e);
        let (status, message) = match e {
            AuthError::EmailExists => (StatusCode::CONFLICT, "Email already registered"),
            AuthError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Registration failed"),
        };
        
        (status, Json(json!({
            "error": "Registration failed",
            "message": message
        })))
    })?;
    
    if result.token.is_empty() {
        Ok("Registration successful. Please check your email to verify your account.")
    } else {
        Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Unexpected response",
            "message": "Invalid server response"
        }))))
    }
}

// 登录处理函数
async fn login(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Extension(app_state): Extension<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> std::result::Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 获取客户端IP
    let client_ip = get_client_ip(&addr, &headers);
    
    // 检查速率限制
    check_rate_limit_for_request(&app_state.rate_limiter, &client_ip, "/api/auth/login").await?;
    
    let default_remaining = app_state.lockout_service.get_config().max_attempts;

    // 检查IP地址锁定（数据库异常时降级，避免把登录整体打成500）
    let ip_lockout_result = match app_state.lockout_service.check_ip_lockout(&client_ip).await {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to check IP lockout: {:?}", e);
            match app_state.db.reauth().await {
                Ok(_) => match app_state.lockout_service.check_ip_lockout(&client_ip).await {
                    Ok(result) => result,
                    Err(retry_err) => {
                        warn!("IP lockout check still failed after reauth, fail-open: {:?}", retry_err);
                        LockoutCheckResult::normal(default_remaining)
                    }
                },
                Err(reauth_err) => {
                    warn!("Reauth failed while checking IP lockout, fail-open: {:?}", reauth_err);
                    LockoutCheckResult::normal(default_remaining)
                }
            }
        }
    };
    
    if ip_lockout_result.is_locked {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(json!({
            "error": "Account locked",
            "message": ip_lockout_result.message,
            "locked_until_seconds": ip_lockout_result.remaining_lockout_seconds
        }))));
    }
    
    // 检查用户账户锁定（数据库异常时降级，避免把登录整体打成500）
    let user_lockout_result = match app_state.lockout_service.check_user_lockout(&req.email).await {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to check user lockout: {:?}", e);
            match app_state.db.reauth().await {
                Ok(_) => match app_state.lockout_service.check_user_lockout(&req.email).await {
                    Ok(result) => result,
                    Err(retry_err) => {
                        warn!("User lockout check still failed after reauth, fail-open: {:?}", retry_err);
                        LockoutCheckResult::normal(default_remaining)
                    }
                },
                Err(reauth_err) => {
                    warn!("Reauth failed while checking user lockout, fail-open: {:?}", reauth_err);
                    LockoutCheckResult::normal(default_remaining)
                }
            }
        }
    };
    
    if user_lockout_result.is_locked {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(json!({
            "error": "Account locked",
            "message": user_lockout_result.message,
            "locked_until_seconds": user_lockout_result.remaining_lockout_seconds
        }))));
    }
    
    // 执行登录逻辑
    let auth_service = AuthService::new(db, config).map_err(|e| {
        error!("Failed to create auth service: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Internal server error",
            "message": "Service unavailable"
        })))
    })?;
    
    let response = auth_service.login(req.email.clone(), req.password).await.map_err(|e| {
        error!("Login failed: {:?}", e);
        
        // 在认证失败时记录锁定尝试
        let should_record_failure = matches!(e, 
            AuthError::InvalidCredentials | 
            AuthError::UserNotFound
        );
        
        if should_record_failure {
            // 异步记录失败尝试，不等待结果以避免阻塞响应
            let lockout_service = app_state.lockout_service.clone();
            let email = req.email.clone();
            let ip = client_ip.clone();
            
            tokio::spawn(async move {
                if let Err(e) = lockout_service.record_failed_user_attempt(&email).await {
                    error!("Failed to record user lockout attempt: {:?}", e);
                }
                if let Err(e) = lockout_service.record_failed_ip_attempt(&ip).await {
                    error!("Failed to record IP lockout attempt: {:?}", e);
                }
            });
        }
        
        let (status, message) = match e {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid email or password"),
            AuthError::EmailNotVerified => (StatusCode::FORBIDDEN, "Email not verified"),
            AuthError::UserNotFound => (StatusCode::UNAUTHORIZED, "Invalid email or password"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Login failed"),
        };
        
        (status, Json(json!({
            "error": "Authentication failed",
            "message": message
        })))
    })?;
    
    // 登录成功，重置失败尝试计数
    let lockout_service = app_state.lockout_service.clone();
    let email = req.email.clone();
    let ip = client_ip.clone();
    
    tokio::spawn(async move {
        if let Err(e) = lockout_service.reset_user_attempts(&email).await {
            error!("Failed to reset user attempts: {:?}", e);
        }
        if let Err(e) = lockout_service.reset_ip_attempts(&ip).await {
            error!("Failed to reset IP attempts: {:?}", e);
        }
    });
    
    Ok(Json(response))
}

// 邮箱验证处理函数
async fn verify_email(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<Json<AuthResponse>> {
    tracing::info!("Starting email verification");
    let auth_service = AuthService::new(db, config)?;
    let result = auth_service.verify_email(token).await;
    match result {
        Ok(auth_response) => Ok(Json(auth_response)),
        Err(e) => {
            error!("Email verification failed: {:?}", e);
            Err(e)
        }
    }
}

// 获取当前用户信息
async fn get_current_user(
    claims: Claims,
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<Json<UserResponse>> {
    let auth_service = AuthService::new(db, config)?;
    match auth_service.get_user_by_id(&claims.sub).await {
        Ok(Some(user)) => Ok(Json(UserResponse::from(user))),
        Ok(None) => {
            warn!("get_current_user: user not found for sub={}, using JWT fallback response", claims.sub);
            let clean_id = claims
                .sub
                .rsplit(':')
                .next()
                .unwrap_or(&claims.sub)
                .trim_matches('`')
                .to_string();

            Ok(Json(UserResponse {
                id: clean_id,
                email: "unknown@example.com".to_string(),
                is_email_verified: true,
                created_at: chrono::Utc::now(),
                has_password: true,
                account_status: crate::models::user::AccountStatus::Active,
                last_login_at: None,
            }))
        }
        Err(e) => {
            warn!(
                "get_current_user: failed to load user for sub={} from DB: {:?}; using JWT fallback response",
                claims.sub, e
            );
            let clean_id = claims
                .sub
                .rsplit(':')
                .next()
                .unwrap_or(&claims.sub)
                .trim_matches('`')
                .to_string();

            Ok(Json(UserResponse {
                id: clean_id,
                email: "unknown@example.com".to_string(),
                is_email_verified: true,
                created_at: chrono::Utc::now(),
                has_password: true,
                account_status: crate::models::user::AccountStatus::Active,
                last_login_at: None,
            }))
        }
    }
}

// Google 登录
async fn google_login(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<axum::response::Redirect> {
    let auth_service = AuthService::new(db, config)?;
    let auth_url = auth_service.get_google_auth_url()?;
    Ok(axum::response::Redirect::to(&auth_url))
}

// Google 回调处理
async fn google_callback(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Query(params): Query<OAuthCallback>,
) -> Result<axum::response::Response> {
    tracing::info!("Starting Google OAuth callback");
    let auth_service = AuthService::new(db, config)?;
    let auth_response = match auth_service.handle_google_callback(params.code).await {
        Ok(response) => response,
        Err(e) => {
            error!("Google callback failed: {:?}", e);
            return Err(e);
        }
    };
    
    // 检查用户是否有密码
    let redirect_url = if !auth_response.user.has_password {
        // 重定向到设置密码页面，并传递 token
        format!("http://129.226.169.63:4173/initialize-password?token={}", auth_response.token)
    } else {
        // 正常重定向到OAuth回调页面，并传递 token
        format!("http://129.226.169.63:4173/oauth/callback?token={}", auth_response.token)
    };

    tracing::info!("OAuth callback completed, redirecting user");
    Ok(axum::response::Redirect::to(&redirect_url).into_response())
}

// GitHub 登录
async fn github_login(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<axum::response::Redirect> {
    let auth_service = AuthService::new(db, config)?;
    let auth_url = auth_service.get_github_auth_url()?;
    Ok(axum::response::Redirect::to(&auth_url))
}

// GitHub 回调处理
async fn github_callback(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Query(params): Query<OAuthCallback>,
) -> Result<axum::response::Response> {
    let auth_service = AuthService::new(db, config)?;
    let auth_response = auth_service.handle_github_callback(params.code).await?;
    
    // 检查用户是否有密码
    let redirect_url = if !auth_response.user.has_password {
        // 重定向到设置密码页面，并传递 token
        format!("http://localhost:5173/initialize-password?token={}", auth_response.token)
    } else {
        // 正常重定向到OAuth回调页面，并传递 token
        format!("http://localhost:5173/oauth/callback?token={}", auth_response.token)
    };

    Ok(axum::response::Redirect::to(&redirect_url).into_response())
}

// 初始化密码处理函数
async fn initialize_password(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Json(request): Json<InitializePasswordRequest>,
) -> Result<Json<UserResponse>> {
    let auth_service = AuthService::new(db, config)?;
    let user = auth_service.initialize_password(&claims.sub, &request.password).await?;
    Ok(Json(user.into()))
}

// 请求密码重置处理函数
async fn request_password_reset(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<RequestPasswordResetRequest>,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.request_password_reset(request.email).await?;
    Ok("Password reset email sent if account exists")
}

// 重置密码处理函数
async fn reset_password(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<ResetPasswordRequest>,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.reset_password(request.token, request.new_password).await?;
    Ok("Password reset successfully")
}

// 登出处理函数
async fn logout(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    claims: Claims,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.logout(bearer.token().to_string()).await?;
    Ok("Logged out successfully")
}

// 登出所有会话处理函数
async fn logout_all(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.logout_all_sessions(&claims.sub).await?;
    Ok("All sessions logged out successfully")
}

// 获取用户会话列表处理函数
async fn get_sessions(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    claims: Claims,
) -> Result<Json<Vec<SessionInfo>>> {
    let auth_service = AuthService::new(db, config)?;
    let sessions = auth_service.get_user_sessions(&claims.sub, bearer.token()).await?;
    Ok(Json(sessions))
}

// 错误处理中间件
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            AuthError::DatabaseError(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AuthError::InvalidCredentials => (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid credentials".to_string(),
            ),
            AuthError::EmailNotVerified => (
                axum::http::StatusCode::FORBIDDEN,
                "Email not verified".to_string(),
            ),
            AuthError::TokenError(_) => (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid token".to_string(),
            ),
            AuthError::UserNotFound => (
                axum::http::StatusCode::NOT_FOUND,
                "User not found".to_string(),
            ),
            AuthError::EmailExists => (
                axum::http::StatusCode::CONFLICT,
                "Email already exists".to_string(),
            ),
            AuthError::InvalidToken => (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid token".to_string(),
            ),
            AuthError::ServerError(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AuthError::OAuthError(_) => (
                axum::http::StatusCode::BAD_REQUEST,
                "OAuth error".to_string(),
            ),
            AuthError::PasswordAlreadySet => (
                axum::http::StatusCode::CONFLICT,
                "Password already set".to_string(),
            ),
            AuthError::InvalidUserId => (
                axum::http::StatusCode::BAD_REQUEST,
                "Invalid user ID".to_string(),
            ),
            AuthError::NotFound(msg) => (
                axum::http::StatusCode::NOT_FOUND,
                msg.clone(),
            ),
            AuthError::ValidationError(msg) => (
                axum::http::StatusCode::BAD_REQUEST,
                msg.clone(),
            ),
            AuthError::PermissionDenied => (
                axum::http::StatusCode::FORBIDDEN,
                "Permission denied".to_string(),
            ),
            AuthError::InsufficientPermissions => (
                axum::http::StatusCode::FORBIDDEN,
                "Insufficient permissions".to_string(),
            ),
            AuthError::AccountSuspended => (
                axum::http::StatusCode::FORBIDDEN,
                "Account suspended".to_string(),
            ),
            AuthError::AccountInactive => (
                axum::http::StatusCode::FORBIDDEN,
                "Account inactive".to_string(),
            ),
            AuthError::AccountDeleted => (
                axum::http::StatusCode::FORBIDDEN,
                "Account deleted".to_string(),
            ),
            AuthError::Forbidden(msg) => (
                axum::http::StatusCode::FORBIDDEN,
                msg.clone(),
            ),
            AuthError::BadRequest(msg) => (
                axum::http::StatusCode::BAD_REQUEST,
                msg.clone(),
            ),
            AuthError::Unauthorized(msg) => (
                axum::http::StatusCode::UNAUTHORIZED,
                msg.clone(),
            ),
            AuthError::InternalServerError(msg) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
            ),
        };

        let body = Json(serde_json::json!({
            "error": message
        }));

        (status, body).into_response()
    }
}
