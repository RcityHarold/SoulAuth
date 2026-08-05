use std::sync::Arc;

use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    error::AuthError,
    models::oidc_client::{CreateOidcClientRequest, OidcClientResponse},
    require_permission,
    services::{database::Database, oidc_client_management::OidcClientService},
    utils::jwt::AuthedUser,
};

/// OIDC 客户端注册表是整个 SSO 的信任根：能改 redirect_uris 就能劫持任意登录。
/// 因此读写分别要求 `oidc_clients.read` / `oidc_clients.write`。
const READ_PERMISSION: &str = "oidc_clients.read";
const WRITE_PERMISSION: &str = "oidc_clients.write";

pub fn oidc_client_routes() -> Router {
    Router::new()
        .route("/clients", post(create_client))
        .route("/clients", get(list_clients))
        .route("/clients/:client_id", get(get_client))
        .route("/clients/:client_id", put(update_client))
        .route("/clients/:client_id", delete(disable_client))
        .route(
            "/clients/:client_id/regenerate-secret",
            post(regenerate_secret),
        )
}

#[derive(Deserialize)]
struct ListClientsQuery {
    limit: Option<i32>,
    offset: Option<i32>,
}

#[derive(Serialize)]
struct ListClientsResponse {
    clients: Vec<OidcClientResponse>,
    total: i32,
    limit: i32,
    offset: i32,
}

#[derive(Serialize)]
struct RegenerateSecretResponse {
    client_secret: String,
    message: String,
}

// 创建 OIDC 客户端
async fn create_client(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Json(request): Json<CreateOidcClientRequest>,
) -> Result<Json<OidcClientResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, WRITE_PERMISSION);

    request
        .validate()
        .map_err(|e| AuthError::BadRequest(format!("Validation error: {}", e)))?;
    validate_redirect_uris(&request)?;

    // created_by 记录真实操作人，不再是硬编码的 "system"。
    match client_service.create_client(request, &user_id).await {
        Ok(client) => Ok(Json(client)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取客户端列表
async fn list_clients(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Query(query): Query<ListClientsQuery>,
) -> Result<Json<ListClientsResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, READ_PERMISSION);

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);

    match client_service.list_clients(Some(limit), Some(offset)).await {
        Ok(clients) => {
            let total = clients.len() as i32;
            Ok(Json(ListClientsResponse {
                clients,
                total,
                limit,
                offset,
            }))
        }
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取单个客户端
async fn get_client(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
) -> Result<Json<OidcClientResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, READ_PERMISSION);

    match client_service.get_client(&client_id).await {
        Ok(client) => Ok(Json(OidcClientResponse {
            client_id: client.client_id,
            client_secret: "***".to_string(), // 不返回密钥
            client_name: client.client_name,
            client_type: client.client_type,
            redirect_uris: client.redirect_uris,
            post_logout_redirect_uris: client.post_logout_redirect_uris,
            allowed_scopes: client.allowed_scopes,
            allowed_grant_types: client.allowed_grant_types,
            allowed_response_types: client.allowed_response_types,
            require_pkce: client.require_pkce,
            access_token_lifetime: client.access_token_lifetime,
            refresh_token_lifetime: client.refresh_token_lifetime,
            id_token_lifetime: client.id_token_lifetime,
            is_active: client.is_active,
            created_at: client.created_at,
            updated_at: client.updated_at,
        })),
        Err(_) => Err(AuthError::NotFound("Client not found".to_string())),
    }
}

// 更新客户端
async fn update_client(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
    Json(request): Json<CreateOidcClientRequest>,
) -> Result<Json<OidcClientResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, WRITE_PERMISSION);

    request
        .validate()
        .map_err(|e| AuthError::BadRequest(format!("Validation error: {}", e)))?;
    validate_redirect_uris(&request)?;

    match client_service.update_client(&client_id, request).await {
        Ok(client) => Ok(Json(client)),
        Err(_) => Err(AuthError::NotFound("Client not found".to_string())),
    }
}

// 禁用客户端
async fn disable_client(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, WRITE_PERMISSION);

    match client_service.disable_client(&client_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(AuthError::NotFound("Client not found".to_string())),
    }
}

// 重新生成客户端密钥
async fn regenerate_secret(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(client_service): Extension<Arc<OidcClientService>>,
    Path(client_id): Path<String>,
) -> Result<Json<RegenerateSecretResponse>, AuthError> {
    let user_id = user.id()?;
    require_permission!(&db, &user_id, WRITE_PERMISSION);

    match client_service.regenerate_client_secret(&client_id).await {
        Ok(new_secret) => Ok(Json(RegenerateSecretResponse {
            client_secret: new_secret,
            message: "Client secret has been regenerated. Please update your application configuration.".to_string(),
        })),
        Err(_) => Err(AuthError::NotFound("Client not found".to_string())),
    }
}

/// 回跳地址必须是绝对 https URL（localhost 放行以便本地开发），且不带 fragment。
fn validate_redirect_uris(request: &CreateOidcClientRequest) -> Result<(), AuthError> {
    let all = request
        .redirect_uris
        .iter()
        .chain(request.post_logout_redirect_uris.iter().flatten());

    for uri in all {
        if uri.contains('#') {
            return Err(AuthError::BadRequest(format!(
                "Redirect URI must not contain a fragment: {uri}"
            )));
        }

        let is_https = uri.starts_with("https://");
        let is_local_http =
            uri.starts_with("http://localhost") || uri.starts_with("http://127.0.0.1");

        if !is_https && !is_local_http {
            return Err(AuthError::BadRequest(format!(
                "Redirect URI must use https (http is only allowed for localhost): {uri}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_redirect_uris;
    use crate::models::oidc_client::{ClientType, CreateOidcClientRequest};

    fn request(redirect_uris: Vec<&str>) -> CreateOidcClientRequest {
        CreateOidcClientRequest {
            client_name: "test".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: redirect_uris.into_iter().map(str::to_string).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_https_and_localhost_redirect_uris() {
        assert!(validate_redirect_uris(&request(vec![
            "https://app.example/cb",
            "http://localhost:3000/cb",
            "http://127.0.0.1:3000/cb",
        ]))
        .is_ok());
    }

    #[test]
    fn rejects_plain_http_and_fragments() {
        assert!(validate_redirect_uris(&request(vec!["http://app.example/cb"])).is_err());
        assert!(validate_redirect_uris(&request(vec!["https://app.example/cb#x"])).is_err());
    }
}
