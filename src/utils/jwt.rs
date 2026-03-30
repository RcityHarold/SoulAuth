use std::sync::Arc;

use crate::{
    error::{AuthError, Result},
    models::{subject::SubjectType, user::User},
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
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub subject_type: Option<SubjectType>,
}

pub fn decode_token_claims(token: &str) -> Result<Claims> {
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| AuthError::InvalidToken)?;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AuthError::InvalidToken)?;

    Ok(token_data.claims)
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        decode_token_claims(bearer.token())
    }
}

pub async fn get_user_from_token(token: &str, db: &Arc<Database>) -> Result<User> {
    let claims = decode_token_claims(token)?;

    let query = "SELECT * FROM user WHERE id = $user_id";
    let mut result = db
        .client
        .query(query)
        .bind(("user_id", claims.sub.clone()))
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    let user: Option<User> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

    user.ok_or(AuthError::UserNotFound)
}

#[cfg(test)]
mod tests {
    use super::Claims;
    use crate::models::subject::SubjectType;

    #[test]
    fn claims_deserialize_old_tokens_without_subject_type() {
        let old_claims = serde_json::json!({
            "sub": "user:legacy",
            "exp": 1,
            "iat": 1,
            "session_id": "session:legacy"
        });

        let claims: Claims =
            serde_json::from_value(old_claims).expect("old claims should deserialize");
        assert_eq!(claims.sub, "user:legacy");
        assert_eq!(claims.subject_type, None);
    }

    #[test]
    fn claims_deserialize_new_tokens_with_subject_type() {
        let new_claims = serde_json::json!({
            "sub": "user:new",
            "exp": 1,
            "iat": 1,
            "session_id": "session:new",
            "subject_type": "human"
        });

        let claims: Claims =
            serde_json::from_value(new_claims).expect("new claims should deserialize");
        assert_eq!(claims.subject_type, Some(SubjectType::Human));
    }
}
