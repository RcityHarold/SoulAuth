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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub subject_type: Option<SubjectType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthSubjectRef {
    UserId(String),
    SubjectId(String),
}

impl Claims {
    pub fn auth_subject_ref(&self) -> AuthSubjectRef {
        if self.sub.starts_with("subject:") {
            return AuthSubjectRef::SubjectId(self.sub.clone());
        }

        AuthSubjectRef::UserId(self.sub.clone())
    }
}

fn decode_claims(token: &str, jwt_secret: &str) -> Result<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AuthError::InvalidToken)?;

    Ok(token_data.claims)
}

async fn resolve_user_by_claims(claims: &Claims, db: &Arc<Database>) -> Result<User> {
    match claims.auth_subject_ref() {
        AuthSubjectRef::UserId(user_id) => db
            .find_record_by_field("user", "id", &user_id)
            .await?
            .ok_or(AuthError::UserNotFound),
        AuthSubjectRef::SubjectId(subject_id) => {
            let query = "SELECT * FROM user WHERE subject_id = type::thing($subject_id) LIMIT 1";
            let mut result = db.client
                .query(query)
                .bind(("subject_id", subject_id))
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            let users: Vec<User> = result.take(0)
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

            users.into_iter().next().ok_or(AuthError::UserNotFound)
        }
    }
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
        
        decode_claims(bearer.token(), &jwt_secret)
    }
}

pub async fn get_user_from_token(token: &str, db: &Arc<Database>) -> Result<User> {
    // 验证 JWT
    let jwt_secret = std::env::var("JWT_SECRET")
        .map_err(|_| AuthError::InvalidToken)?;

    let claims = decode_claims(token, &jwt_secret)?;
    resolve_user_by_claims(&claims, db).await
}

#[cfg(test)]
mod tests {
    use super::{decode_claims, AuthSubjectRef, Claims};
    use crate::models::subject::SubjectType;
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[test]
    fn claims_deserialize_old_tokens_without_subject_type() {
        let old_claims = serde_json::json!({
            "sub": "user:legacy",
            "exp": 1,
            "iat": 1,
            "session_id": "session:legacy"
        });

        let claims: Claims = serde_json::from_value(old_claims).expect("old claims should deserialize");
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

        let claims: Claims = serde_json::from_value(new_claims).expect("new claims should deserialize");
        assert_eq!(claims.subject_type, Some(SubjectType::Human));
    }

    #[test]
    fn claims_resolve_legacy_user_subject_ref() {
        let claims = Claims {
            sub: "user:legacy".to_string(),
            exp: 1,
            iat: 1,
            session_id: None,
            subject_type: None,
        };

        assert_eq!(claims.auth_subject_ref(), AuthSubjectRef::UserId("user:legacy".to_string()));
    }

    #[test]
    fn claims_resolve_subject_subject_ref() {
        let claims = Claims {
            sub: "subject:new".to_string(),
            exp: 1,
            iat: 1,
            session_id: None,
            subject_type: Some(SubjectType::Human),
        };

        assert_eq!(claims.auth_subject_ref(), AuthSubjectRef::SubjectId("subject:new".to_string()));
    }

    #[test]
    fn decode_legacy_token_keeps_user_lookup_path() {
        let claims = Claims {
            sub: "user:legacy".to_string(),
            exp: 4_102_444_800,
            iat: 1,
            session_id: Some("session:legacy".to_string()),
            subject_type: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("test-secret".as_bytes()),
        )
        .expect("legacy token should encode");

        let decoded = decode_claims(&token, "test-secret").expect("legacy token should decode");
        assert_eq!(decoded.auth_subject_ref(), AuthSubjectRef::UserId("user:legacy".to_string()));
    }

    #[test]
    fn decode_subject_token_keeps_subject_lookup_path() {
        let claims = Claims {
            sub: "subject:new".to_string(),
            exp: 4_102_444_800,
            iat: 1,
            session_id: Some("session:new".to_string()),
            subject_type: Some(SubjectType::Human),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("test-secret".as_bytes()),
        )
        .expect("subject token should encode");

        let decoded = decode_claims(&token, "test-secret").expect("subject token should decode");
        assert_eq!(decoded.auth_subject_ref(), AuthSubjectRef::SubjectId("subject:new".to_string()));
    }
}
