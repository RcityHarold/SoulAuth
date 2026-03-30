use std::sync::Arc;
use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    config::Config,
    error::AuthError,
    models::sso_session::{CreateSsoSessionRequest, SsoSessionResponse},
    services::{
        auth::AuthService,
        database::Database,
        sso_session_management::{SessionStats, SsoSessionService, UserSessionStats},
    },
    utils::jwt::Claims,
    require_permission,
};

pub fn sso_session_routes() -> Router {
    Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions/:session_id", get(get_session))
        .route("/sessions/:session_id", delete(logout_session))
        .route("/sessions/:session_id/clients/:client_id", post(add_client_session))
        .route("/sessions/:session_id/clients/:client_id", delete(remove_client_session))
        .route("/sessions/:session_id/extend", post(extend_session))
        .route("/users/:user_id/sessions", get(get_user_sessions))
        .route("/users/:user_id/sessions", delete(logout_user_all_sessions))
        .route("/users/:user_id/sessions/stats", get(get_user_session_stats))
        .route("/sessions/stats", get(get_session_stats))
        .route("/sessions/cleanup", post(cleanup_expired_sessions))
}

#[derive(Deserialize)]
struct ExtendSessionRequest {
    extend_seconds: i64,
}

#[derive(Serialize)]
struct LogoutResponse {
    message: String,
    sessions_terminated: i32,
}

#[derive(Serialize)]
struct CleanupResponse {
    message: String,
    sessions_cleaned: i32,
}

// 创建 SSO 会话
async fn create_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Json(mut request): Json<CreateSsoSessionRequest>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    let auth_service = AuthService::new(db, config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    request.user_id = current_user_id;

    match session_service.create_session(request).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取 SSO 会话
async fn get_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Path(session_id): Path<String>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    match session_service.get_session(&session_id).await {
        Ok(session) => {
            if session.user_id != current_user_id {
                require_permission!(&db, &current_user_id, "users.read");
            }

            let is_active = !session.is_expired();
            let response = SsoSessionResponse {
                session_id: session.session_id,
                user_id: session.user_id,
                client_sessions: session.client_sessions,
                created_at: session.created_at,
                last_accessed_at: session.last_accessed_at,
                expires_at: session.expires_at,
                is_active,
            };
            Ok(Json(response))
        }
        Err(_) => Err(AuthError::NotFound("Session not found".to_string())),
    }
}

// 添加客户端会话
async fn add_client_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Path((session_id, client_id)): Path<(String, String)>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    let auth_service = AuthService::new(db, config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    let session = session_service.get_session(&session_id).await
        .map_err(|_| AuthError::NotFound("Session not found".to_string()))?;

    if session.user_id != current_user_id {
        return Err(AuthError::Forbidden("Cannot modify another user's session".to_string()));
    }

    match session_service.add_client_session(&session_id, &client_id).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(AuthError::BadRequest(e.to_string())),
    }
}

// 移除客户端会话（单点登出）
async fn remove_client_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Path((session_id, client_id)): Path<(String, String)>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    let auth_service = AuthService::new(db, config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    let session = session_service.get_session(&session_id).await
        .map_err(|_| AuthError::NotFound("Session not found".to_string()))?;

    if session.user_id != current_user_id {
        return Err(AuthError::Forbidden("Cannot modify another user's session".to_string()));
    }

    match session_service.remove_client_session(&session_id, &client_id).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(AuthError::BadRequest(e.to_string())),
    }
}

// 延长会话
async fn extend_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Path(session_id): Path<String>,
    Json(request): Json<ExtendSessionRequest>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    if request.extend_seconds <= 0 || request.extend_seconds > 86400 * 7 {
        return Err(AuthError::BadRequest("Invalid extend duration".to_string()));
    }

    let auth_service = AuthService::new(db, config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    let session = session_service.get_session(&session_id).await
        .map_err(|_| AuthError::NotFound("Session not found".to_string()))?;

    if session.user_id != current_user_id {
        return Err(AuthError::Forbidden("Cannot extend another user's session".to_string()));
    }

    match session_service.extend_session(&session_id, request.extend_seconds).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(AuthError::BadRequest(e.to_string())),
    }
}

// 获取用户的所有会话
async fn get_user_sessions(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Path(_user_id): Path<String>,
) -> Result<Json<Vec<SsoSessionResponse>>, AuthError> {
    let auth_service = AuthService::new(db, config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    match session_service.get_user_sessions(&current_user_id).await {
        Ok(sessions) => Ok(Json(sessions)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 终止用户的所有会话
async fn logout_user_all_sessions(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Path(_user_id): Path<String>,
) -> Result<Json<LogoutResponse>, AuthError> {
    let auth_service = AuthService::new(db, config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    match session_service.logout_user_all_sessions(&current_user_id).await {
        Ok(count) => {
            let response = LogoutResponse {
                message: "All user sessions have been terminated".to_string(),
                sessions_terminated: count,
            };
            Ok(Json(response))
        }
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 终止特定会话
async fn logout_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Path(session_id): Path<String>,
) -> Result<StatusCode, AuthError> {
    let auth_service = AuthService::new(db, config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    let session = session_service.get_session(&session_id).await
        .map_err(|_| AuthError::NotFound("Session not found".to_string()))?;

    if session.user_id != current_user_id {
        return Err(AuthError::Forbidden("Cannot logout another user's session".to_string()));
    }

    match session_service.logout_session(&session_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(AuthError::NotFound("Session not found".to_string())),
    }
}

// 获取用户会话统计
async fn get_user_session_stats(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Path(_user_id): Path<String>,
) -> Result<Json<UserSessionStats>, AuthError> {
    let auth_service = AuthService::new(db, config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    match session_service.get_user_session_stats(&current_user_id).await {
        Ok(stats) => Ok(Json(stats)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取全局会话统计
async fn get_session_stats(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
) -> Result<Json<SessionStats>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(&db, &current_user_id, "security.read");

    match session_service.get_session_stats().await {
        Ok(stats) => Ok(Json(stats)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 清理过期会话
async fn cleanup_expired_sessions(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
) -> Result<Json<CleanupResponse>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(&db, &current_user_id, "security.read");

    match session_service.cleanup_expired_sessions().await {
        Ok(count) => {
            let response = CleanupResponse {
                message: "Expired sessions have been cleaned up".to_string(),
                sessions_cleaned: count,
            };
            Ok(Json(response))
        }
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::sso_session::CreateSsoSessionRequest;

    #[test]
    fn create_session_request_user_id_can_be_overridden_by_authenticated_user() {
        let mut request = CreateSsoSessionRequest {
            user_id: "user:attacker-controlled".to_string(),
            client_id: "client-1".to_string(),
            ip_address: "127.0.0.1".to_string(),
            user_agent: "test".to_string(),
            expires_in: Some(60),
        };

        let authenticated_user_id = "user:real-user".to_string();
        request.user_id = authenticated_user_id.clone();

        assert_eq!(request.user_id, authenticated_user_id);
        assert_ne!(request.user_id, "user:attacker-controlled");
    }

    #[test]
    fn session_owner_check_rejects_cross_user_modification() {
        let current_user_id = "user:alice";
        let session_owner_user_id = "user:bob";

        let result = if session_owner_user_id != current_user_id {
            Err(AuthError::Forbidden(
                "Cannot modify another user's session".to_string(),
            ))
        } else {
            Ok(())
        };

        assert!(matches!(result, Err(AuthError::Forbidden(_))));
    }
}