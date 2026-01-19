use std::sync::Arc;
use crate::{
    error::{AuthError, Result},
    models::user::User,
    services::database::Database,
};
use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::request::Parts,
    RequestPartsExt,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub session_id: Option<String>,
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        // 从请求头中提取 Bearer token
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        // 验证 JWT
        let jwt_secret = std::env::var("JWT_SECRET")
            .map_err(|_| AuthError::InvalidToken)?;
        
        let token_data = decode::<Claims>(
            bearer.token(),
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

pub async fn get_user_from_token(token: &str, db: &Arc<Database>) -> Result<User> {
    // 验证 JWT
    let jwt_secret = std::env::var("JWT_SECRET")
        .map_err(|_| AuthError::InvalidToken)?;
    
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AuthError::InvalidToken)?;

    // 从数据库获取用户
    let query = "SELECT * FROM user WHERE id = $user_id";
    let mut result = db.client
        .query(query)
        .bind(("user_id", token_data.claims.sub.clone()))
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    let user: Option<User> = result.take(0)
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
    
    user.ok_or(AuthError::UserNotFound)
}
