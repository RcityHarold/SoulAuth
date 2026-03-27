use axum::http::{StatusCode, header};
use thiserror::Error;
use surrealdb::Error as SurrealDBError;

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
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Internal server error: {0}")]
    InternalServerError(String),
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

pub type Result<T> = std::result::Result<T, AuthError>;

// 为了兼容，添加 AppError 别名
pub type AppError = AuthError;
