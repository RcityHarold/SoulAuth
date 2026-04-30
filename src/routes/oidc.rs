use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Extension, Form, OriginalUri, Query},
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Json, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::Deserialize;
use serde_json::json;

use crate::{
    config::Config,
    error::AuthError,
    models::{
        oidc_client::{OidcClient, ResponseType},
        oidc_token::{TokenRequest, AuthorizeRequest, UserInfoResponse},
        user::User,
    },
    services::{
        database::Database,
        oidc::{JwksResponse, OidcConfiguration, OidcService},
    },
    utils::{
        jwt::get_user_from_token,
        record_id::{record_id_key_to_string, user_record_id},
    },
};

pub(crate) const SOULAUTH_SESSION_COOKIE: &str = "soulauth_session";
pub(crate) const OIDC_RETURN_COOKIE: &str = "soulauth_oidc_return";
pub(crate) const SESSION_TTL_SECONDS: i64 = 86400;

#[derive(Debug, serde::Serialize, Deserialize)]
struct BrowserSessionClaims {
    sub: String,
    exp: i64,
    iat: i64,
}

#[derive(Debug, serde::Serialize, Deserialize)]
struct OidcReturnClaims {
    target: String,
    exp: i64,
    iat: i64,
}

pub(crate) fn build_cookie(name: &str, value: &str, max_age_seconds: i64) -> String {
    format!(
        "{}={}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
        name,
        urlencoding::encode(value),
        max_age_seconds
    )
}

pub(crate) fn build_expired_cookie(name: &str) -> String {
    build_cookie(name, "", 0)
}

pub(crate) fn create_browser_session_token(
    user_id: &str,
    jwt_secret: &str,
) -> Result<String, AuthError> {
    create_browser_session_token_with_ttl(user_id, jwt_secret, SESSION_TTL_SECONDS)
}

fn create_browser_session_token_with_ttl(
    user_id: &str,
    jwt_secret: &str,
    ttl_seconds: i64,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let claims = BrowserSessionClaims {
        sub: user_id.to_string(),
        exp: now + ttl_seconds,
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AuthError::TokenError(e.to_string()))
}

pub(crate) fn decode_browser_session_token(
    token: &str,
    jwt_secret: &str,
) -> Result<String, AuthError> {
    let mut validation = Validation::default();
    validation.leeway = 0;
    let token_data = decode::<BrowserSessionClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AuthError::InvalidToken)?;

    Ok(token_data.claims.sub)
}

pub(crate) fn create_oidc_return_token(
    target: &str,
    jwt_secret: &str,
) -> Result<String, AuthError> {
    create_oidc_return_token_with_ttl(target, jwt_secret, 600)
}

fn create_oidc_return_token_with_ttl(
    target: &str,
    jwt_secret: &str,
    ttl_seconds: i64,
) -> Result<String, AuthError> {
    if !is_valid_oidc_return_target(target) {
        return Err(AuthError::BadRequest("Invalid OIDC return target".to_string()));
    }

    sign_oidc_return_token_unchecked(target, jwt_secret, ttl_seconds)
}

fn sign_oidc_return_token_unchecked(
    target: &str,
    jwt_secret: &str,
    ttl_seconds: i64,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let claims = OidcReturnClaims {
        target: target.to_string(),
        exp: now + ttl_seconds,
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AuthError::TokenError(e.to_string()))
}

pub(crate) fn decode_oidc_return_token(
    token: &str,
    jwt_secret: &str,
) -> Result<String, AuthError> {
    let mut validation = Validation::default();
    validation.leeway = 0;
    let token_data = decode::<OidcReturnClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AuthError::InvalidToken)?;

    if !is_valid_oidc_return_target(&token_data.claims.target) {
        return Err(AuthError::InvalidToken);
    }

    Ok(token_data.claims.target)
}

fn is_valid_oidc_return_target(target: &str) -> bool {
    target.starts_with("/api/oidc/authorize?") && !target.starts_with("//")
}

pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|cookie_header| cookie_header.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(cookie_name, cookie_value)| {
            if cookie_name == name {
                urlencoding::decode(cookie_value).ok().map(|value| value.into_owned())
            } else {
                None
            }
        })
}

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
    OriginalUri(original_uri): OriginalUri,
    Extension(oidc_service): Extension<Arc<OidcService>>,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    headers: HeaderMap,
) -> Result<Response, AuthError> {
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

    validate_authorize_request(&db, &request).await?;

    // 检查用户是否已登录
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                if let Ok(user) = get_user_from_token(token, &db).await {
                    // 用户已登录，生成授权码
                    let user_id = record_id_key_to_string(&user.id.unwrap());
                    return create_authorize_response(&oidc_service, &request, &user_id).await;
                }
            }
        }
    }

    if let Some(session_token) = cookie_value(&headers, SOULAUTH_SESSION_COOKIE) {
        if let Ok(user_id) = decode_browser_session_token(&session_token, &config.jwt_secret) {
            if let Ok(user_id) = resolve_existing_user_id(&db, &user_id).await {
                return create_authorize_response(&oidc_service, &request, &user_id).await;
            }
        }
    }

    // 用户未登录，保存原始 OIDC 请求并重定向到 Google 登录
    let auth_base = config.app_url.trim_end_matches('/');
    let return_url = format!("{auth_base}{original_uri}");
    let return_token = create_oidc_return_token(&return_url, &config.jwt_secret)?;
    let return_cookie = build_cookie(OIDC_RETURN_COOKIE, &return_token, 600);
    let google_login_url = format!("{auth_base}/api/auth/login/google");
    let mut response = Redirect::to(&google_login_url).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&return_cookie)
            .map_err(|e| AuthError::BadRequest(format!("Invalid return cookie: {e}")))?,
    );
    Ok(response)
}

async fn validate_authorize_request(
    db: &Arc<Database>,
    request: &AuthorizeRequest,
) -> Result<(), AuthError> {
    let query = r#"
        SELECT
            <string>id AS id,
            client_id,
            client_secret_hash,
            client_name,
            client_type,
            redirect_uris,
            post_logout_redirect_uris,
            allowed_scopes,
            allowed_grant_types,
            allowed_response_types,
            require_pkce,
            access_token_lifetime,
            refresh_token_lifetime,
            id_token_lifetime,
            is_active,
            <string>created_by AS created_by,
            created_at,
            updated_at
        FROM oidc_client
        WHERE client_id = $client_id AND is_active = true
        LIMIT 1
    "#;

    let mut result = db
        .raw_query(
            "validate_oidc_client",
            query,
            json!({
                "client_id": request.client_id,
            }),
        )
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to validate OIDC client: {e}")))?;

    let clients: Vec<serde_json::Value> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse OIDC client: {e}")))?;
    let clients: Vec<OidcClient> = clients
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse OIDC client: {e}")))?;
    let client = clients
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::BadRequest("Invalid OIDC client".to_string()))?;

    if !client.redirect_uris.contains(&request.redirect_uri) {
        return Err(AuthError::BadRequest("Invalid redirect URI".to_string()));
    }

    let response_types = parse_response_types(&request.response_type)?;
    for response_type in response_types {
        if !client.allowed_response_types.contains(&response_type) {
            return Err(AuthError::BadRequest("Response type not allowed".to_string()));
        }
    }

    if client.require_pkce && request.code_challenge.is_none() {
        return Err(AuthError::BadRequest("PKCE is required".to_string()));
    }

    Ok(())
}

fn parse_response_types(response_type: &str) -> Result<Vec<ResponseType>, AuthError> {
    let response_types: Vec<ResponseType> = response_type
        .split_whitespace()
        .map(|value| match value {
            "code" => Ok(ResponseType::Code),
            "id_token" => Ok(ResponseType::IdToken),
            _ => Err(AuthError::BadRequest("Unsupported response type".to_string())),
        })
        .collect::<Result<Vec<_>, _>>()?;

    if response_types.is_empty() {
        return Err(AuthError::BadRequest("Missing response type".to_string()));
    }

    Ok(response_types)
}

async fn resolve_existing_user_id(
    db: &Arc<Database>,
    user_id: &str,
) -> Result<String, AuthError> {
    let query = "SELECT * FROM user WHERE id = $user_id LIMIT 1";
    let mut result = match db
        .client
        .query(query)
        .bind(("user_id", user_record_id(user_id)))
        .await
    {
        Ok(result) => result,
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("401") || msg.contains("Unauthorized") {
                let fresh = db.fresh_client().await.map_err(|e| {
                    AuthError::DatabaseError(format!("Failed to refresh database client: {e}"))
                })?;
                fresh
                    .query(query)
                    .bind(("user_id", user_record_id(user_id)))
                    .await
                    .map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to resolve session user: {e}"))
                    })?
            } else {
                return Err(AuthError::DatabaseError(format!(
                    "Failed to resolve session user: {err}"
                )));
            }
        }
    };

    let users: Vec<User> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse session user: {e}")))?;
    let user = users.into_iter().next().ok_or(AuthError::UserNotFound)?;
    let user_id = user.id.as_ref().ok_or(AuthError::UserNotFound)?;

    Ok(record_id_key_to_string(user_id))
}

async fn create_authorize_response(
    oidc_service: &OidcService,
    request: &AuthorizeRequest,
    user_id: &str,
) -> Result<Response, AuthError> {
    match oidc_service.create_authorization_code(request, user_id).await {
        Ok(code) => {
            let mut redirect_url = format!("{}?code={}", request.redirect_uri, code);
            if let Some(state) = &request.state {
                redirect_url.push_str(&format!("&state={}", state));
            }
            Ok(Redirect::to(&redirect_url).into_response())
        }
        Err(e) => {
            Err(AuthError::BadRequest(e.to_string()))
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{
        build_cookie, build_expired_cookie, create_browser_session_token,
        create_browser_session_token_with_ttl, create_oidc_return_token,
        decode_browser_session_token, decode_oidc_return_token,
        sign_oidc_return_token_unchecked, OIDC_RETURN_COOKIE, SOULAUTH_SESSION_COOKIE,
    };

    #[test]
    fn build_cookie_encodes_value_and_sets_browser_security_attributes() {
        let cookie = build_cookie(OIDC_RETURN_COOKIE, "/api/oidc/authorize?state=a b", 60);

        assert_eq!(
            cookie,
            "soulauth_oidc_return=%2Fapi%2Foidc%2Fauthorize%3Fstate%3Da%20b; Path=/; Max-Age=60; HttpOnly; Secure; SameSite=Lax"
        );
    }

    #[test]
    fn build_expired_cookie_clears_value() {
        let cookie = build_expired_cookie(OIDC_RETURN_COOKIE);

        assert_eq!(
            cookie,
            "soulauth_oidc_return=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
        );
    }

    #[test]
    fn browser_session_token_round_trips_user_id() {
        let secret = "test-secret";
        let token = create_browser_session_token("user-123", secret).expect("token");

        let user_id = decode_browser_session_token(&token, secret).expect("decoded user id");

        assert_eq!(user_id, "user-123");
    }

    #[test]
    fn browser_session_token_rejects_wrong_secret() {
        let token = create_browser_session_token("user-123", "correct-secret").expect("token");

        let result = decode_browser_session_token(&token, "wrong-secret");

        assert!(result.is_err());
    }

    #[test]
    fn browser_session_token_rejects_expired_token() {
        let token = create_browser_session_token_with_ttl("user-123", "test-secret", -1)
            .expect("token");

        let result = decode_browser_session_token(&token, "test-secret");

        assert!(result.is_err());
    }

    #[test]
    fn signed_return_cookie_round_trips_internal_authorize_target() {
        let target = "/api/oidc/authorize?client_id=client&redirect_uri=https%3A%2F%2Fapp.example%2Fcb";
        let token = create_oidc_return_token(target, "test-secret").expect("token");

        let decoded = decode_oidc_return_token(&token, "test-secret").expect("target");

        assert_eq!(decoded, target);
    }

    #[test]
    fn tampered_return_cookie_is_rejected() {
        let target = "/api/oidc/authorize?client_id=client";
        let mut token = create_oidc_return_token(target, "test-secret").expect("token");
        token.push_str("tampered");

        let result = decode_oidc_return_token(&token, "test-secret");

        assert!(result.is_err());
    }

    #[test]
    fn expired_return_cookie_is_rejected() {
        let target = "/api/oidc/authorize?client_id=client";
        let token = sign_oidc_return_token_unchecked(target, "test-secret", -1)
            .expect("token");

        let result = decode_oidc_return_token(&token, "test-secret");

        assert!(result.is_err());
    }

    #[test]
    fn external_return_cookie_target_is_rejected() {
        let token = sign_oidc_return_token_unchecked(
            "https://evil.example/api/oidc/authorize",
            "test-secret",
            600,
        )
        .expect("token");

        let result = decode_oidc_return_token(&token, "test-secret");

        assert!(result.is_err());
    }

    #[test]
    fn browser_session_cookie_name_is_stable() {
        assert_eq!(SOULAUTH_SESSION_COOKIE, "soulauth_session");
    }
}
