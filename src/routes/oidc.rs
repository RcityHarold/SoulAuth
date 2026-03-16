use std::sync::Arc;
use std::collections::HashMap;

use axum::{
    extract::{Extension, Query, Form},
    http::{HeaderMap, header},
    response::{Redirect, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize};
use serde_json::json;
use base64::{Engine as _, engine::general_purpose};

use crate::{
    config::Config,
    models::{
        oidc_token::{TokenRequest, AuthorizeRequest, UserInfoResponse},
    },
    services::{
        oidc::{OidcService, OidcConfiguration, JwksResponse},
        database::Database,
    },
    error::AuthError,
    utils::jwt::get_user_from_token,
};

pub fn oidc_routes() -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(openid_configuration))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .route("/logout", get(logout))
}

// OIDC Discovery Endpoint
async fn openid_configuration(
    Extension(oidc_service): Extension<Arc<OidcService>>,
) -> Result<Json<OidcConfiguration>, AuthError> {
    let config = oidc_service.get_configuration();
    Ok(Json(config))
}

// JSON Web Key Set
async fn jwks(
    Extension(oidc_service): Extension<Arc<OidcService>>,
) -> Result<Json<JwksResponse>, AuthError> {
    // 暂时返回空的 JWKS，因为我们使用对称密钥
    // 在生产环境中应该使用 RSA 公钥
    let jwks = JwksResponse {
        keys: vec![],
    };
    Ok(Json(jwks))
}

// 授权端点
async fn authorize(
    Query(params): Query<HashMap<String, String>>,
    Extension(oidc_service): Extension<Arc<OidcService>>,
    Extension(db): Extension<Arc<Database>>,
    headers: HeaderMap,
) -> Result<impl axum::response::IntoResponse, AuthError> {
    // 解析授权请求参数
    let request = AuthorizeRequest {
        response_type: params.get("response_type")
            .ok_or_else(|| AuthError::BadRequest("Missing response_type".to_string()))?
            .clone(),
        client_id: params.get("client_id")
            .ok_or_else(|| AuthError::BadRequest("Missing client_id".to_string()))?
            .clone(),
        redirect_uri: params.get("redirect_uri")
            .ok_or_else(|| AuthError::BadRequest("Missing redirect_uri".to_string()))?
            .clone(),
        scope: params.get("scope").cloned(),
        state: params.get("state").cloned(),
        nonce: params.get("nonce").cloned(),
        code_challenge: params.get("code_challenge").cloned(),
        code_challenge_method: params.get("code_challenge_method").cloned(),
        prompt: params.get("prompt").cloned(),
        max_age: params.get("max_age").and_then(|s| s.parse().ok()),
    };

    // 检查用户是否已登录
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                if let Ok(user) = get_user_from_token(token, &db).await {
                    // 用户已登录，生成授权码
                    match oidc_service.create_authorization_code(&request, &crate::utils::record_id::record_id_key_to_string(&user.id.unwrap())).await {
                        Ok(code) => {
                            let mut redirect_url = format!("{}?code={}", request.redirect_uri, code);
                            if let Some(state) = request.state {
                                redirect_url.push_str(&format!("&state={}", state));
                            }
                            return Ok(Redirect::to(&redirect_url));
                        }
                        Err(e) => {
                            let error_url = format!("{}?error=server_error&error_description={}", 
                                                   request.redirect_uri, 
                                                   urlencoding::encode(&e.to_string()));
                            return Ok(Redirect::to(&error_url));
                        }
                    }
                }
            }
        }
    }

    // 用户未登录，重定向到登录页面
    let login_url = format!("/login?{}", serde_urlencoded::to_string(&params).unwrap_or_default());
    Ok(Redirect::to(&login_url))
}

// 令牌端点
async fn token(
    Extension(oidc_service): Extension<Arc<OidcService>>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<serde_json::Value>, AuthError> {
    match oidc_service.exchange_code_for_tokens(&request).await {
        Ok(token_response) => Ok(Json(serde_json::to_value(token_response)?)),
        Err(e) => {
            let error_response = json!({
                "error": "invalid_request",
                "error_description": e.to_string()
            });
            Err(AuthError::BadRequest(error_response.to_string()))
        }
    }
}

// 用户信息端点
async fn userinfo(
    Extension(oidc_service): Extension<Arc<OidcService>>,
    headers: HeaderMap,
) -> Result<Json<UserInfoResponse>, AuthError> {
    // 从 Authorization header 获取访问令牌
    let auth_header = headers.get(header::AUTHORIZATION)
        .ok_or_else(|| AuthError::Unauthorized("Missing authorization header".to_string()))?;
    
    let auth_str = auth_header.to_str()
        .map_err(|_| AuthError::Unauthorized("Invalid authorization header".to_string()))?;
    
    if !auth_str.starts_with("Bearer ") {
        return Err(AuthError::Unauthorized("Invalid token type".to_string()));
    }
    
    let access_token = &auth_str[7..];
    
    match oidc_service.get_userinfo(access_token).await {
        Ok(userinfo) => Ok(Json(userinfo)),
        Err(e) => Err(AuthError::Unauthorized(e.to_string())),
    }
}

// 登出端点
async fn logout(
    Query(params): Query<HashMap<String, String>>,
    Extension(config): Extension<Arc<Config>>,
) -> Result<impl axum::response::IntoResponse, AuthError> {
    // 获取登出后重定向 URI
    let post_logout_redirect_uri = params.get("post_logout_redirect_uri");
    let id_token_hint = params.get("id_token_hint");
    let state = params.get("state");

    // TODO: 验证 id_token_hint 并执行登出逻辑
    // TODO: 撤销相关的令牌和会话

    // 构建重定向 URL
    let redirect_url = if let Some(redirect_uri) = post_logout_redirect_uri {
        let mut url = redirect_uri.clone();
        if let Some(state_value) = state {
            url.push_str(&format!("?state={}", state_value));
        }
        url
    } else {
        // 默认重定向到应用首页
        config.app_url.clone()
    };

    Ok(Redirect::to(&redirect_url))
}

// 错误处理辅助函数
fn create_error_redirect(redirect_uri: &str, error: &str, description: Option<&str>, state: Option<&str>) -> String {
    let mut url = format!("{}?error={}", redirect_uri, error);
    
    if let Some(desc) = description {
        url.push_str(&format!("&error_description={}", urlencoding::encode(desc)));
    }
    
    if let Some(state_value) = state {
        url.push_str(&format!("&state={}", state_value));
    }
    
    url
}

#[derive(Deserialize)]
struct ClientCredentials {
    client_id: String,
    client_secret: String,
}

// 中间件：客户端认证
async fn authenticate_client(
    headers: HeaderMap,
    form: Option<Form<ClientCredentials>>,
) -> Result<(String, String), AuthError> {
    // 尝试从 Authorization header 获取客户端凭据
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Basic ") {
                let encoded = &auth_str[6..];
                if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(encoded) {
                    if let Ok(credentials) = String::from_utf8(decoded_bytes) {
                        let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                        if parts.len() == 2 {
                            return Ok((parts[0].to_string(), parts[1].to_string()));
                        }
                    }
                }
            }
        }
    }

    // 尝试从表单数据获取客户端凭据
    if let Some(Form(creds)) = form {
        return Ok((creds.client_id, creds.client_secret));
    }

    Err(AuthError::Unauthorized("Missing client credentials".to_string()))
}