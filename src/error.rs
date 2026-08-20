use axum::http::header;
use thiserror::Error;
use surrealdb::Error as SurrealDBError;

/// `enum_variant_names`：这里多数变体都以 `Error` 结尾，clippy 会提示改名。
/// 不改 —— `DatabaseError` / `TokenError` / `OAuthError` 这套命名在错误类型里
/// 是通行读法，去掉后缀（`Database` / `Token`）反而看不出是错误；
/// 而重命名要动两百多个调用点，换来的只是少一条 lint。
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Email not verified")]
    EmailNotVerified,
    
    #[error("Token error: {0}")]
    TokenError(String),
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Email already exists")]
    EmailExists,

    #[error("Username already exists")]
    UsernameExists,
    
    #[error("Invalid token")]
    InvalidToken,
    
    #[error("Server error: {0}")]
    ServerError(String),
    
    #[error("OAuth error: {0}")]
    OAuthError(String),
    
    #[error("Password already set")]
    PasswordAlreadySet,
    
    #[error("Invalid user ID")]
    InvalidUserId,
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Permission denied")]
    PermissionDenied,
    
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    
    #[error("Account suspended")]
    AccountSuspended,
    
    #[error("Account inactive")]
    AccountInactive,
    
    #[error("Account deleted")]
    AccountDeleted,
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Bad request: {0}")]
    BadRequest(String),
    /// 该功能未在本部署中启用（例如没有配置第三方登录的凭证）。
    ///
    /// 与 404 的区别：路由存在、语义明确，只是本实例没开。运维看到 501
    /// 就知道该去补配置，而 404 会让人以为版本不对或路由写错了。
    #[error("Not configured: {0}")]
    NotConfigured(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl From<reqwest::Error> for AuthError {
    fn from(err: reqwest::Error) -> Self {
        AuthError::OAuthError(err.to_string())
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(err: serde_json::Error) -> Self {
        AuthError::ServerError(format!("JSON error: {}", err))
    }
}

impl From<header::InvalidHeaderValue> for AuthError {
    fn from(err: header::InvalidHeaderValue) -> Self {
        AuthError::ServerError(format!("Invalid header value: {}", err))
    }
}

impl From<SurrealDBError> for AuthError {
    fn from(err: SurrealDBError) -> Self {
        AuthError::DatabaseError(err.to_string())
    }
}

impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        use axum::{http::StatusCode, Json};

        if matches!(
            self,
            AuthError::DatabaseError(_) | AuthError::ServerError(_)
        ) {
            tracing::error!("AuthError response: {}", self);
        }

        // 服务端内部错误一律返回统一文案，不把底层细节（SQL、连接串等）泄露给调用方。
        let (status, message) = match &self {
            AuthError::DatabaseError(_) | AuthError::ServerError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AuthError::InvalidCredentials => {
                (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())
            }
            AuthError::EmailNotVerified => {
                (StatusCode::FORBIDDEN, "Email not verified".to_string())
            }
            AuthError::TokenError(_) | AuthError::InvalidToken => {
                (StatusCode::UNAUTHORIZED, "Invalid token".to_string())
            }
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
            AuthError::EmailExists => (StatusCode::CONFLICT, "Email already exists".to_string()),
            AuthError::UsernameExists => {
                (StatusCode::CONFLICT, "Username already exists".to_string())
            }
            AuthError::OAuthError(_) => (StatusCode::BAD_REQUEST, "OAuth error".to_string()),
            AuthError::PasswordAlreadySet => {
                (StatusCode::CONFLICT, "Password already set".to_string())
            }
            AuthError::InvalidUserId => (StatusCode::BAD_REQUEST, "Invalid user ID".to_string()),
            AuthError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AuthError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AuthError::PermissionDenied => {
                (StatusCode::FORBIDDEN, "Permission denied".to_string())
            }
            AuthError::InsufficientPermissions => (
                StatusCode::FORBIDDEN,
                "Insufficient permissions".to_string(),
            ),
            AuthError::AccountSuspended => {
                (StatusCode::FORBIDDEN, "Account suspended".to_string())
            }
            AuthError::AccountInactive => (StatusCode::FORBIDDEN, "Account inactive".to_string()),
            AuthError::AccountDeleted => (StatusCode::FORBIDDEN, "Account deleted".to_string()),
            AuthError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AuthError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AuthError::NotConfigured(msg) => (StatusCode::NOT_IMPLEMENTED, msg.clone()),
            AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AuthError>;

// 为了兼容，添加 AppError 别名
pub type AppError = AuthError;
