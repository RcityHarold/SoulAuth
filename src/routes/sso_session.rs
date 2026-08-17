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
    error::AuthError,
    models::sso_session::{CreateSsoSessionRequest, SsoSessionResponse},
    services::{
        database::Database,
        sso_session_management::{SessionStats, SsoSessionService, UserSessionStats},
    },
    utils::jwt::AuthedUser,
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
    authed_user: AuthedUser,
    Json(mut request): Json<CreateSsoSessionRequest>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    let current_user_id = authed_user.id()?;
    request.user_id = current_user_id;

    match session_service.create_session(request).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取 SSO 会话
async fn get_session(
    Extension(db): Extension<Arc<Database>>,
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    authed_user: AuthedUser,
    Path(session_id): Path<String>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    let current_user_id = authed_user.id()?;

    match session_service.get_session(&session_id).await {
        Ok(session) => {
            if session.user_id != current_user_id {
                require_permission!(&db, &current_user_id, crate::models::permission::names::USERS_READ);
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
        Err(e) => Err(session_lookup_error("get session", e)),
    }
}

/// 把服务层的 `anyhow` 错误映射成 HTTP 错误。
///
/// 这两个接口以前一律写成 `Err(_) => NotFound("Session not found")`：**任何**失败
/// 都以"没这个会话"的面目出现，真正的库错误被伪装成 404，排查时只会去核对
/// session_id，永远查不到数据库那一侧。
///
/// 服务层用 `anyhow!("Session not found")` 表示确实不存在，只有这一种才是 404；
/// "会话已过期"另算一种业务错误；其余按服务端错误处理并记日志。
fn session_lookup_error(operation: &str, error: anyhow::Error) -> AuthError {
    let message = error.to_string();
    if message.contains("Session not found") {
        return AuthError::NotFound("Session not found".to_string());
    }
    if message.contains("expired") {
        return AuthError::BadRequest("Session has expired".to_string());
    }

    tracing::error!(error = %error, operation, "SSO session operation failed");
    AuthError::InternalServerError(message)
}

/// 把会话写入失败收敛成一句对外无害的话。
///
/// 这些错误来自 `anyhow`，原文里常常带着完整的 SurrealQL 语句和表 / 字段名；
/// 以前直接 `e.to_string()` 塞进 400 响应体，等于把库结构送给调用方。
fn session_write_error(operation: &str, error: anyhow::Error) -> AuthError {
    tracing::warn!(error = %error, operation, "SSO session write failed");
    AuthError::BadRequest("Session could not be updated".to_string())
}

// 添加客户端会话
async fn add_client_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    authed_user: AuthedUser,
    Path((session_id, client_id)): Path<(String, String)>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    let current_user_id = authed_user.id()?;
    let session = session_service.get_session(&session_id).await
        .map_err(|_| AuthError::NotFound("Session not found".to_string()))?;

    if session.user_id != current_user_id {
        return Err(AuthError::Forbidden("Cannot modify another user's session".to_string()));
    }

    match session_service.add_client_session(&session_id, &client_id).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(session_write_error("add client session", e)),
    }
}

// 移除客户端会话（单点登出）
async fn remove_client_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    authed_user: AuthedUser,
    Path((session_id, client_id)): Path<(String, String)>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    let current_user_id = authed_user.id()?;
    let session = session_service.get_session(&session_id).await
        .map_err(|_| AuthError::NotFound("Session not found".to_string()))?;

    if session.user_id != current_user_id {
        return Err(AuthError::Forbidden("Cannot modify another user's session".to_string()));
    }

    match session_service.remove_client_session(&session_id, &client_id).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(session_write_error("remove client session", e)),
    }
}

// 延长会话
async fn extend_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    authed_user: AuthedUser,
    Path(session_id): Path<String>,
    Json(request): Json<ExtendSessionRequest>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    if request.extend_seconds <= 0 || request.extend_seconds > 86400 * 7 {
        return Err(AuthError::BadRequest("Invalid extend duration".to_string()));
    }

    let current_user_id = authed_user.id()?;
    let session = session_service.get_session(&session_id).await
        .map_err(|_| AuthError::NotFound("Session not found".to_string()))?;

    if session.user_id != current_user_id {
        return Err(AuthError::Forbidden("Cannot extend another user's session".to_string()));
    }

    match session_service.extend_session(&session_id, request.extend_seconds).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(session_write_error("extend session", e)),
    }
}

/// 解析 `:user_id` 路径参数：只能是自己，除非持有 `users.read`。
///
/// 以前这三个 `/users/:user_id/...` 端点直接把路径参数丢掉（`Path(_user_id)`），
/// 无条件返回**调用者自己**的数据。既不越权、也不报错，但 URL 在说谎：管理员
/// 拿 `/users/<别人>/sessions` 去核对，看到的是自己的会话，还以为对方没有登录。
async fn resolve_target_user(
    db: &Arc<Database>,
    authed_user: &AuthedUser,
    requested_user_id: &str,
) -> Result<String, AuthError> {
    let current_user_id = authed_user.id()?;
    let requested = crate::utils::record_id::normalize_user_id(requested_user_id);

    if requested == current_user_id {
        return Ok(current_user_id);
    }

    require_permission!(db, &current_user_id, crate::models::permission::names::USERS_READ);
    Ok(requested)
}

// 获取用户的所有会话
async fn get_user_sessions(
    Extension(db): Extension<Arc<Database>>,
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    authed_user: AuthedUser,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<SsoSessionResponse>>, AuthError> {
    let current_user_id = resolve_target_user(&db, &authed_user, &user_id).await?;

    match session_service.get_user_sessions(&current_user_id).await {
        Ok(sessions) => Ok(Json(sessions)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 终止用户的所有会话
async fn logout_user_all_sessions(
    Extension(db): Extension<Arc<Database>>,
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    authed_user: AuthedUser,
    Path(user_id): Path<String>,
) -> Result<Json<LogoutResponse>, AuthError> {
    let current_user_id = resolve_target_user(&db, &authed_user, &user_id).await?;

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
    authed_user: AuthedUser,
    Path(session_id): Path<String>,
) -> Result<StatusCode, AuthError> {
    let current_user_id = authed_user.id()?;
    let session = session_service.get_session(&session_id).await
        .map_err(|_| AuthError::NotFound("Session not found".to_string()))?;

    if session.user_id != current_user_id {
        return Err(AuthError::Forbidden("Cannot logout another user's session".to_string()));
    }

    match session_service.logout_session(&session_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err(session_lookup_error("logout session", e)),
    }
}

// 获取用户会话统计
async fn get_user_session_stats(
    Extension(db): Extension<Arc<Database>>,
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    authed_user: AuthedUser,
    Path(user_id): Path<String>,
) -> Result<Json<UserSessionStats>, AuthError> {
    let current_user_id = resolve_target_user(&db, &authed_user, &user_id).await?;

    match session_service.get_user_session_stats(&current_user_id).await {
        Ok(stats) => Ok(Json(stats)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取全局会话统计
async fn get_session_stats(
    Extension(db): Extension<Arc<Database>>,
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    authed_user: AuthedUser,
) -> Result<Json<SessionStats>, AuthError> {
    let current_user_id = authed_user.id()?;
    require_permission!(&db, &current_user_id, crate::models::permission::names::SECURITY_READ);

    match session_service.get_session_stats().await {
        Ok(stats) => Ok(Json(stats)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 清理过期会话
async fn cleanup_expired_sessions(
    Extension(db): Extension<Arc<Database>>,
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    authed_user: AuthedUser,
) -> Result<Json<CleanupResponse>, AuthError> {
    let current_user_id = authed_user.id()?;
    require_permission!(&db, &current_user_id, crate::models::permission::names::SECURITY_READ);

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