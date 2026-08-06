use std::sync::Arc;

use anyhow::{anyhow, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, Validation};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::Config,
    models::{
        oidc_client::{ClientType, GrantType, OidcClient, ResponseType},
        oidc_token::{
            AuthorizeRequest, IdTokenClaims, OidcAccessToken, OidcAuthorizationCode,
            OidcRefreshToken, TokenRequest, TokenResponse, UserInfoResponse,
        },
        user::User,
    },
    services::{database::Database, oidc_keys::OidcSigningKey},
    utils::record_id::normalize_user_id,
};

pub use crate::services::oidc_keys::JwksResponse;

#[derive(Clone)]
pub struct OidcService {
    db: Arc<Database>,
    config: Config,
    signing_key: Arc<OidcSigningKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

impl OidcService {
    pub fn new(db: Arc<Database>, config: Config, signing_key: Arc<OidcSigningKey>) -> Result<Self> {
        Ok(Self {
            db,
            config,
            signing_key,
        })
    }

    // OIDC Discovery Endpoint
    pub fn get_configuration(&self) -> OidcConfiguration {
        let base_url = self.config.app_url.trim_end_matches('/');

        OidcConfiguration {
            issuer: base_url.to_string(),
            authorization_endpoint: format!("{}/api/oidc/authorize", base_url),
            token_endpoint: format!("{}/api/oidc/token", base_url),
            userinfo_endpoint: format!("{}/api/oidc/userinfo", base_url),
            jwks_uri: format!("{}/api/oidc/jwks", base_url),
            end_session_endpoint: format!("{}/api/oidc/logout", base_url),
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            // 与实际签名算法保持一致：公钥通过 jwks_uri 暴露。
            id_token_signing_alg_values_supported: vec!["RS256".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_post".to_string(),
                "client_secret_basic".to_string(),
                "none".to_string(),
            ],
            // 只保留 S256：plain 起不到防授权码拦截的作用。
            code_challenge_methods_supported: vec!["S256".to_string()],
        }
    }

    pub fn jwks(&self) -> JwksResponse {
        self.signing_key.jwks()
    }

    // 授权码流程 - 生成授权码
    pub async fn create_authorization_code(
        &self,
        request: &AuthorizeRequest,
        user_id: &str,
    ) -> Result<String> {
        // 验证客户端
        let client = self
            .get_client(&request.client_id)
            .await
            .map_err(|e| anyhow!("get client failed: {e}"))?;
        if !client.is_active {
            return Err(anyhow!("Client is not active"));
        }

        // 验证重定向URI
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(anyhow!("Invalid redirect URI"));
        }

        // 验证响应类型
        let response_types: Vec<ResponseType> = request
            .response_type
            .split_whitespace()
            .map(|rt| match rt {
                "code" => Ok(ResponseType::Code),
                "id_token" => Ok(ResponseType::IdToken),
                _ => Err(anyhow!("Unsupported response type")),
            })
            .collect::<Result<Vec<_>>>()?;

        for rt in &response_types {
            if !client.allowed_response_types.contains(rt) {
                return Err(anyhow!("Response type not allowed for this client"));
            }
        }

        // 验证 PKCE (如果客户端要求)
        if client.require_pkce && request.code_challenge.is_none() {
            return Err(anyhow!("PKCE is required for this client"));
        }

        // 只收 S256。发现文档里 `code_challenge_methods_supported` 就只列了 S256，
        // 但这里以前不校验 method，缺省会按 `plain` 处理 —— plain 的 challenge 等于
        // verifier 本身，谁能看到授权请求（Referer、浏览器历史、同设备的其他 App）
        // 谁就直接拿到了 verifier，PKCE 等于没有。不认下发时就拒，别留到兑换阶段。
        if request.code_challenge.is_some() {
            match request.code_challenge_method.as_deref() {
                Some("S256") => {}
                Some(other) => {
                    return Err(anyhow!(
                        "Unsupported code_challenge_method '{other}': only S256 is supported"
                    ))
                }
                None => {
                    return Err(anyhow!(
                        "code_challenge_method is required and must be S256"
                    ))
                }
            }
        }

        // 生成授权码
        let code = generate_random_string(32);
        let expires_at = Utc::now().timestamp() + 600; // 10分钟过期
        let scope = self.resolve_scope(&client, request.scope.as_deref())?;

        let auth_code = OidcAuthorizationCode {
            id: None,
            code: code.clone(),
            client_id: request.client_id.clone(),
            user_id: user_id.to_string(),
            redirect_uri: request.redirect_uri.clone(),
            scope,
            state: request.state.clone(),
            nonce: request.nonce.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method.clone(),
            used: false,
            expires_at,
            created_at: Utc::now().timestamp(),
        };

        // 保存授权码
        self.save_authorization_code(&auth_code).await?;

        Ok(code)
    }

    /// 把请求的 scope 收敛到客户端被允许的集合内，未申请时回落到 `openid`。
    fn resolve_scope(&self, client: &OidcClient, requested: Option<&str>) -> Result<String> {
        let requested = requested.unwrap_or("openid").trim();
        if requested.is_empty() {
            return Ok("openid".to_string());
        }

        let mut granted: Vec<String> = Vec::new();
        for scope in requested.split_whitespace() {
            if !client
                .allowed_scopes
                .iter()
                .any(|allowed| allowed.as_str() == scope)
            {
                return Err(anyhow!("Scope not allowed for this client: {scope}"));
            }
            if !granted.iter().any(|existing| existing.as_str() == scope) {
                granted.push(scope.to_string());
            }
        }

        Ok(granted.join(" "))
    }

    // 令牌端点 - 交换授权码获取令牌
    pub async fn exchange_code_for_tokens(&self, request: &TokenRequest) -> Result<TokenResponse> {
        match request.grant_type.as_str() {
            "authorization_code" => self.handle_authorization_code_grant(request).await,
            "refresh_token" => self.handle_refresh_token_grant(request).await,
            _ => Err(anyhow!("Unsupported grant type")),
        }
    }

    /// 统一的客户端认证：机密客户端必须提供且校验通过 client_secret。
    async fn authenticate_client(&self, request: &TokenRequest) -> Result<OidcClient> {
        let client = self.get_client(&request.client_id).await?;

        match (&client.client_type, request.client_secret.as_deref()) {
            (ClientType::Confidential, None) => {
                Err(anyhow!("Client secret required for confidential clients"))
            }
            (_, Some(secret)) => {
                if self.verify_client_secret(&client, secret)? {
                    Ok(client)
                } else {
                    Err(anyhow!("Invalid client credentials"))
                }
            }
            (ClientType::Public, None) => Ok(client),
        }
    }

    async fn handle_authorization_code_grant(
        &self,
        request: &TokenRequest,
    ) -> Result<TokenResponse> {
        let code = request
            .code
            .as_ref()
            .ok_or_else(|| anyhow!("Missing authorization code"))?;
        let redirect_uri = request
            .redirect_uri
            .as_ref()
            .ok_or_else(|| anyhow!("Missing redirect URI"))?;

        let client = self.authenticate_client(request).await?;
        if !client
            .allowed_grant_types
            .contains(&GrantType::AuthorizationCode)
        {
            return Err(anyhow!("Grant type not allowed for this client"));
        }

        // 获取并验证授权码
        let mut auth_code = self
            .get_authorization_code(code)
            .await
            .map_err(|e| anyhow!("get authorization code failed: {e}"))?;
        if auth_code.used {
            return Err(anyhow!("Authorization code already used"));
        }
        if auth_code.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Authorization code expired"));
        }
        if auth_code.client_id != request.client_id {
            return Err(anyhow!("Authorization code was not issued to this client"));
        }
        if auth_code.redirect_uri != *redirect_uri {
            return Err(anyhow!("Redirect URI mismatch"));
        }

        // 验证 PKCE
        if let Some(code_challenge) = &auth_code.code_challenge {
            let code_verifier = request
                .code_verifier
                .as_ref()
                .ok_or_else(|| anyhow!("Code verifier required"))?;

            if !self.verify_pkce(
                code_challenge,
                &auth_code.code_challenge_method,
                code_verifier,
            )? {
                return Err(anyhow!("Invalid code verifier"));
            }
        }

        // 标记授权码为已使用. The guarded update prevents concurrent redemptions.
        auth_code.used = true;
        self.update_authorization_code(&auth_code)
            .await
            .map_err(|e| anyhow!("mark authorization code used failed: {e}"))?;

        // 生成令牌
        self.generate_tokens(
            &client,
            &auth_code.user_id,
            &auth_code.scope,
            auth_code.nonce.as_deref(),
        )
        .await
        .map_err(|e| anyhow!("generate tokens failed: {e}"))
    }

    async fn handle_refresh_token_grant(&self, request: &TokenRequest) -> Result<TokenResponse> {
        let refresh_token = request
            .refresh_token
            .as_ref()
            .ok_or_else(|| anyhow!("Missing refresh token"))?;

        let client = self.authenticate_client(request).await?;
        if !client.allowed_grant_types.contains(&GrantType::RefreshToken) {
            return Err(anyhow!("Grant type not allowed for this client"));
        }

        // 获取并验证刷新令牌
        let stored_refresh_token = self.get_refresh_token(refresh_token).await?;
        if stored_refresh_token.client_id != request.client_id {
            return Err(anyhow!("Refresh token was not issued to this client"));
        }
        if stored_refresh_token.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Refresh token expired"));
        }
        if stored_refresh_token.used {
            // 复用已轮换过的刷新令牌通常意味着令牌泄露：直接吊销该用户在该客户端上的全部令牌。
            self.revoke_client_tokens_for_user(
                &stored_refresh_token.client_id,
                &stored_refresh_token.user_id,
            )
            .await?;
            return Err(anyhow!("Refresh token already used"));
        }

        // 原子地标记旧刷新令牌为已使用，避免并发重放
        if !self.consume_refresh_token(&stored_refresh_token.token).await? {
            return Err(anyhow!("Refresh token already used"));
        }

        // 使旧的访问令牌失效
        self.revoke_access_token(&stored_refresh_token.access_token)
            .await?;

        // 刷新时不允许提权：新 scope 必须是原 scope 的子集
        let scope = match request.scope.as_deref() {
            None => stored_refresh_token.scope.clone(),
            Some(requested) => {
                let original: Vec<&str> = stored_refresh_token.scope.split_whitespace().collect();
                for scope in requested.split_whitespace() {
                    if !original.contains(&scope) {
                        return Err(anyhow!("Requested scope exceeds the original grant"));
                    }
                }
                requested.to_string()
            }
        };

        self.generate_tokens(&client, &stored_refresh_token.user_id, &scope, None)
            .await
    }

    async fn generate_tokens(
        &self,
        client: &OidcClient,
        user_id: &str,
        scope: &str,
        nonce: Option<&str>,
    ) -> Result<TokenResponse> {
        let now = Utc::now().timestamp();

        // 生成访问令牌
        let access_token = generate_random_string(32);
        let access_token_expires_at = now + client.access_token_lifetime;

        let oidc_access_token = OidcAccessToken {
            id: None,
            token: access_token.clone(),
            token_type: "Bearer".to_string(),
            client_id: client.client_id.clone(),
            user_id: user_id.to_string(),
            scope: scope.to_string(),
            expires_at: access_token_expires_at,
            created_at: now,
        };

        self.save_access_token(&oidc_access_token)
            .await
            .map_err(|e| anyhow!("save access token failed: {e}"))?;

        // 生成刷新令牌
        let refresh_token = if client.allowed_grant_types.contains(&GrantType::RefreshToken) {
            let token = generate_random_string(48);
            let refresh_token_expires_at = now + client.refresh_token_lifetime;

            let oidc_refresh_token = OidcRefreshToken {
                id: None,
                token: token.clone(),
                client_id: client.client_id.clone(),
                user_id: user_id.to_string(),
                access_token: access_token.clone(),
                scope: scope.to_string(),
                used: false,
                expires_at: refresh_token_expires_at,
                created_at: now,
            };

            self.save_refresh_token(&oidc_refresh_token)
                .await
                .map_err(|e| anyhow!("save refresh token failed: {e}"))?;
            Some(token)
        } else {
            None
        };

        // 生成 ID 令牌（如果 scope 包含 openid）
        let id_token = if scope.split_whitespace().any(|value| value == "openid") {
            let user = self
                .get_user_by_id(user_id)
                .await
                .map_err(|e| anyhow!("get id token user failed: {e}"))?;
            Some(self.generate_id_token(client, &user, nonce).await?)
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: client.access_token_lifetime,
            refresh_token,
            id_token,
            scope: scope.to_string(),
        })
    }

    async fn generate_id_token(
        &self,
        client: &OidcClient,
        user: &User,
        nonce: Option<&str>,
    ) -> Result<String> {
        let now = Utc::now().timestamp();
        let exp = now + client.id_token_lifetime;

        let claims = IdTokenClaims {
            iss: self.issuer(),
            sub: crate::utils::record_id::record_id_key_to_string(
                user.id.as_ref().ok_or_else(|| anyhow!("User has no id"))?,
            ),
            aud: client.client_id.clone(),
            exp,
            iat: now,
            auth_time: user.last_login_at.unwrap_or(now),
            nonce: nonce.map(|n| n.to_string()),
            email: Some(user.email.clone()),
            email_verified: Some(user.is_email_verified),
            name: None, // 需要从用户档案获取
            preferred_username: Some(user.username.clone()),
            profile: None,
            picture: None,
        };

        encode(
            &self.signing_key.jwt_header(),
            &claims,
            self.signing_key.encoding_key(),
        )
        .map_err(|e| anyhow!("Failed to generate ID token: {}", e))
    }

    fn issuer(&self) -> String {
        self.config.app_url.trim_end_matches('/').to_string()
    }

    /// 校验 RP 在登出请求里带上的 `id_token_hint`，返回 (user_id, client_id)。
    pub fn verify_id_token_hint(&self, id_token: &str) -> Result<(String, String)> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer()]);
        // 登出时 ID Token 通常已经过期，这里只关心签名与归属；
        // `aud` 不设置即表示不校验（jsonwebtoken 只在 `validation.aud` 存在时比对）。
        validation.validate_exp = false;

        let token_data = decode::<IdTokenClaims>(id_token, self.signing_key.decoding_key(), &validation)
            .map_err(|e| anyhow!("Invalid id_token_hint: {e}"))?;

        Ok((token_data.claims.sub, token_data.claims.aud))
    }

    // UserInfo 端点
    pub async fn get_userinfo(&self, access_token: &str) -> Result<UserInfoResponse> {
        let token = self.get_access_token(access_token).await?;
        if token.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Access token expired"));
        }

        let scopes: Vec<&str> = token.scope.split_whitespace().collect();
        if !scopes.contains(&"openid") {
            return Err(anyhow!("Access token does not carry the openid scope"));
        }

        let user = self.get_user_by_id(&token.user_id).await?;
        let include_email = scopes.contains(&"email");
        let include_profile = scopes.contains(&"profile");

        Ok(UserInfoResponse {
            sub: crate::utils::record_id::record_id_key_to_string(
                user.id.as_ref().ok_or_else(|| anyhow!("User has no id"))?,
            ),
            email: include_email.then(|| user.email.clone()),
            email_verified: include_email.then_some(user.is_email_verified),
            name: None, // 需要从用户档案获取
            preferred_username: include_profile.then(|| user.username.clone()),
            profile: None,
            picture: None,
            updated_at: include_profile.then_some(user.updated_at),
        })
    }

    // 辅助方法
    fn verify_client_secret(&self, client: &OidcClient, provided_secret: &str) -> Result<bool> {
        Ok(verify_client_secret_hash(
            &client.client_secret_hash,
            provided_secret,
        ))
    }

    fn verify_pkce(
        &self,
        code_challenge: &str,
        method: &Option<String>,
        code_verifier: &str,
    ) -> Result<bool> {
        Self::verify_pkce_value(code_challenge, method.as_deref(), code_verifier)
    }

    pub(crate) fn verify_pkce_value(
        code_challenge: &str,
        method: Option<&str>,
        code_verifier: &str,
    ) -> Result<bool> {
        if !(43..=128).contains(&code_verifier.len()) {
            return Err(anyhow!(
                "Invalid code verifier: length must be between 43 and 128 characters"
            ));
        }

        if !code_verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
        {
            return Err(anyhow!(
                "Invalid code verifier: contains characters outside RFC 7636 charset"
            ));
        }

        // 授权阶段已经把非 S256 拦在门外了，这里不再兜底 `plain`：
        // 留着它，存量的 plain 授权码或将来某条绕过下发校验的路径就还能降级。
        match method {
            Some("S256") => {
                let hash = Sha256::digest(code_verifier.as_bytes());
                let encoded = general_purpose::URL_SAFE_NO_PAD.encode(hash);
                Ok(constant_time_eq(encoded.as_bytes(), code_challenge.as_bytes()))
            }
            Some(other) => Err(anyhow!("Unsupported code challenge method: {}", other)),
            None => Err(anyhow!("Missing code_challenge_method; S256 is required")),
        }
    }

    pub async fn get_client(&self, client_id: &str) -> Result<OidcClient> {
        let query = r#"
            SELECT
                type::string(id) AS id,
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
                type::string(created_by) AS created_by,
                created_at,
                updated_at
            FROM oidc_client
            WHERE client_id = $client_id AND is_active = true
            LIMIT 1
        "#;

        let mut result = self
            .db
            .raw_query(
                "oidc_get_client",
                query,
                serde_json::json!({ "client_id": client_id }),
            )
            .await?;

        let clients: Vec<serde_json::Value> = result.take(0)?;
        let clients: Vec<OidcClient> = clients
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        clients
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Client not found"))
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<User> {
        let users: Vec<User> = self
            .db
            .query_take0_vec(
                "oidc_get_user_by_id",
                "SELECT * FROM user WHERE id = type::record('user', $user_key) LIMIT 1",
                serde_json::json!({ "user_key": normalize_user_id(user_id) }),
            )
            .await?;

        users
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("User not found"))
    }

    async fn save_authorization_code(&self, code: &OidcAuthorizationCode) -> Result<()> {
        let query = r#"
            CREATE oidc_authorization_code CONTENT {
                code: $code,
                client_id: $client_id,
                user_id: type::record('user', $user_key),
                redirect_uri: $redirect_uri,
                scope: $scope,
                -- `Option::None` 经 JSON 绑定会变成 NULL，而 `option<string>` 列
                -- 只接受 NONE（报 "Expected `none | string` but found `NULL`"）。
                -- `?? NONE` 把两者归一。
                state: $state ?? NONE,
                nonce: $nonce ?? NONE,
                code_challenge: $code_challenge ?? NONE,
                code_challenge_method: $code_challenge_method ?? NONE,
                used: $used,
                expires_at: $expires_at,
                created_at: $created_at
            }
        "#;

        self.db
            .raw_query(
                "oidc_save_authorization_code",
                query,
                serde_json::json!({
                    "code": code.code,
                    "client_id": code.client_id,
                    "user_key": normalize_user_id(&code.user_id),
                    "redirect_uri": code.redirect_uri,
                    "scope": code.scope,
                    "state": code.state,
                    "nonce": code.nonce,
                    "code_challenge": code.code_challenge,
                    "code_challenge_method": code.code_challenge_method,
                    "used": code.used,
                    "expires_at": code.expires_at,
                    "created_at": code.created_at,
                }),
            )
            .await?;

        Ok(())
    }

    async fn get_authorization_code(&self, code: &str) -> Result<OidcAuthorizationCode> {
        let query = r#"
            SELECT
                type::string(id) AS id,
                code,
                client_id,
                type::string(user_id) AS user_id,
                redirect_uri,
                scope,
                state,
                nonce,
                code_challenge,
                code_challenge_method,
                used,
                expires_at,
                created_at
            FROM oidc_authorization_code
            WHERE code = $code
            LIMIT 1
        "#;

        let mut result = self
            .db
            .raw_query(
                "oidc_get_authorization_code",
                query,
                serde_json::json!({ "code": code }),
            )
            .await?;

        let codes: Vec<serde_json::Value> = result.take(0)?;
        codes
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<OidcAuthorizationCode>, _>>()?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Authorization code not found"))
    }

    async fn update_authorization_code(&self, code: &OidcAuthorizationCode) -> Result<()> {
        let query =
            "UPDATE oidc_authorization_code SET used = true WHERE code = $code AND used = false RETURN VALUE code";
        let mut result = self
            .db
            .raw_query(
                "oidc_update_authorization_code",
                query,
                serde_json::json!({ "code": code.code }),
            )
            .await?;

        let updated_codes: Vec<String> = result.take(0)?;
        if updated_codes.len() == 1 {
            Ok(())
        } else {
            Err(anyhow!("Authorization code already used"))
        }
    }

    async fn save_access_token(&self, token: &OidcAccessToken) -> Result<()> {
        let query = r#"
            CREATE oidc_access_token CONTENT {
                token: $access_token_value,
                token_type: $token_type,
                client_id: $client_id,
                user_id: type::record('user', $user_key),
                scope: $scope,
                expires_at: $expires_at,
                created_at: $created_at
            }
        "#;

        self.db
            .raw_query(
                "oidc_save_access_token",
                query,
                serde_json::json!({
                    "access_token_value": token.token,
                    "token_type": token.token_type,
                    "client_id": token.client_id,
                    "user_key": normalize_user_id(&token.user_id),
                    "scope": token.scope,
                    "expires_at": token.expires_at,
                    "created_at": token.created_at,
                }),
            )
            .await?;

        Ok(())
    }

    async fn get_access_token(&self, token: &str) -> Result<OidcAccessToken> {
        let query = r#"
            SELECT
                type::string(id) AS id,
                token,
                token_type,
                client_id,
                type::string(user_id) AS user_id,
                scope,
                expires_at,
                created_at
            FROM oidc_access_token
            WHERE token = $access_token_value
            LIMIT 1
        "#;

        let mut result = self
            .db
            .raw_query(
                "oidc_get_access_token",
                query,
                serde_json::json!({ "access_token_value": token }),
            )
            .await?;

        let tokens: Vec<serde_json::Value> = result.take(0)?;
        tokens
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<OidcAccessToken>, _>>()?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Access token not found"))
    }

    async fn revoke_access_token(&self, token: &str) -> Result<()> {
        self.db
            .raw_query(
                "oidc_revoke_access_token",
                "DELETE oidc_access_token WHERE token = $access_token_value",
                serde_json::json!({ "access_token_value": token }),
            )
            .await?;

        Ok(())
    }

    async fn save_refresh_token(&self, token: &OidcRefreshToken) -> Result<()> {
        let query = r#"
            CREATE oidc_refresh_token CONTENT {
                token: $refresh_token_value,
                client_id: $client_id,
                user_id: type::record('user', $user_key),
                access_token: $access_token,
                scope: $scope,
                used: $used,
                expires_at: $expires_at,
                created_at: $created_at
            }
        "#;

        self.db
            .raw_query(
                "oidc_save_refresh_token",
                query,
                serde_json::json!({
                    "refresh_token_value": token.token,
                    "client_id": token.client_id,
                    "user_key": normalize_user_id(&token.user_id),
                    "access_token": token.access_token,
                    "scope": token.scope,
                    "used": token.used,
                    "expires_at": token.expires_at,
                    "created_at": token.created_at,
                }),
            )
            .await?;

        Ok(())
    }

    async fn get_refresh_token(&self, token: &str) -> Result<OidcRefreshToken> {
        let query = r#"
            SELECT
                type::string(id) AS id,
                token,
                client_id,
                type::string(user_id) AS user_id,
                access_token,
                scope,
                used,
                expires_at,
                created_at
            FROM oidc_refresh_token
            WHERE token = $refresh_token_value
            LIMIT 1
        "#;

        let mut result = self
            .db
            .raw_query(
                "oidc_get_refresh_token",
                query,
                serde_json::json!({ "refresh_token_value": token }),
            )
            .await?;

        let tokens: Vec<serde_json::Value> = result.take(0)?;
        tokens
            .into_iter()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<OidcRefreshToken>, _>>()?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Refresh token not found"))
    }

    /// 原子地把刷新令牌标记为已使用；返回 false 表示已经被别的请求消费掉了。
    async fn consume_refresh_token(&self, token: &str) -> Result<bool> {
        let query = "UPDATE oidc_refresh_token SET used = true WHERE token = $refresh_token_value AND used = false RETURN VALUE token";

        let mut result = self
            .db
            .raw_query(
                "oidc_consume_refresh_token",
                query,
                serde_json::json!({ "refresh_token_value": token }),
            )
            .await?;

        let updated: Vec<String> = result.take(0)?;
        Ok(updated.len() == 1)
    }

    /// 吊销某用户在某客户端上的全部访问 / 刷新令牌（单点登出、令牌泄露时使用）。
    pub async fn revoke_client_tokens_for_user(
        &self,
        client_id: &str,
        user_id: &str,
    ) -> Result<()> {
        let bindings = serde_json::json!({
            "client_id": client_id,
            "user_key": normalize_user_id(user_id),
        });

        self.db
            .raw_query(
                "oidc_revoke_access_tokens_for_client",
                "DELETE oidc_access_token WHERE client_id = $client_id AND user_id = type::record('user', $user_key)",
                bindings.clone(),
            )
            .await?;
        self.db
            .raw_query(
                "oidc_revoke_refresh_tokens_for_client",
                "DELETE oidc_refresh_token WHERE client_id = $client_id AND user_id = type::record('user', $user_key)",
                bindings,
            )
            .await?;

        Ok(())
    }

    /// 吊销某用户在**所有**客户端上的令牌（全局登出）。
    pub async fn revoke_all_tokens_for_user(&self, user_id: &str) -> Result<()> {
        let bindings = serde_json::json!({ "user_key": normalize_user_id(user_id) });

        self.db
            .raw_query(
                "oidc_revoke_all_access_tokens",
                "DELETE oidc_access_token WHERE user_id = type::record('user', $user_key)",
                bindings.clone(),
            )
            .await?;
        self.db
            .raw_query(
                "oidc_revoke_all_refresh_tokens",
                "DELETE oidc_refresh_token WHERE user_id = type::record('user', $user_key)",
                bindings,
            )
            .await?;

        Ok(())
    }

    /// 清理过期的授权码与令牌，由后台定时任务调用。
    pub async fn cleanup_expired_artifacts(&self) -> Result<()> {
        let now = serde_json::json!({ "now": Utc::now().timestamp() });

        for (op, sql) in [
            (
                "oidc_cleanup_codes",
                "DELETE oidc_authorization_code WHERE expires_at < $now",
            ),
            (
                "oidc_cleanup_access_tokens",
                "DELETE oidc_access_token WHERE expires_at < $now",
            ),
            (
                "oidc_cleanup_refresh_tokens",
                "DELETE oidc_refresh_token WHERE expires_at < $now",
            ),
        ] {
            self.db.raw_query(op, sql, now.clone()).await?;
        }

        Ok(())
    }
}

/// 生成 client_secret 的存储哈希（Argon2id）。
pub fn hash_client_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| anyhow!("Failed to hash client secret: {e}"))
}

/// 校验 client_secret。
///
/// 兼容历史上用裸 SHA-256 存储的记录（走常量时间比较），新写入一律是 Argon2。
pub fn verify_client_secret_hash(stored_hash: &str, provided_secret: &str) -> bool {
    if stored_hash.starts_with("$argon2") {
        return PasswordHash::new(stored_hash)
            .map(|parsed| {
                Argon2::default()
                    .verify_password(provided_secret.as_bytes(), &parsed)
                    .is_ok()
            })
            .unwrap_or(false);
    }

    let legacy = format!("{:x}", Sha256::digest(provided_secret.as_bytes()));
    constant_time_eq(legacy.as_bytes(), stored_hash.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn generate_random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_eq, hash_client_secret, verify_client_secret_hash, OidcService,
    };
    use base64::{engine::general_purpose, Engine as _};
    use sha2::{Digest, Sha256};

    #[test]
    fn verifies_s256_pkce_challenge() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let challenge =
            general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let result = OidcService::verify_pkce_value(&challenge, Some("S256"), verifier);
        assert!(result.expect("pkce verification should succeed"));
    }

    #[test]
    fn rejects_wrong_s256_pkce_challenge() {
        let result = OidcService::verify_pkce_value(
            "wrong",
            Some("S256"),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
        );
        assert!(!result.expect("pkce verification should return false"));
    }

    #[test]
    fn rejects_plain_pkce_challenge() {
        // plain 的 challenge 就是 verifier 本身，等于没有 PKCE；发现文档也只宣告 S256。
        let verifier = "plain-verifier-abcdefghijklmnopqrstuvwxyz012345";
        let err = OidcService::verify_pkce_value(verifier, Some("plain"), verifier)
            .expect_err("plain must be rejected");
        assert!(err.to_string().contains("Unsupported code challenge method"));
    }

    #[test]
    fn rejects_pkce_without_challenge_method() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        let err = OidcService::verify_pkce_value(verifier, None, verifier)
            .expect_err("missing method must be rejected");
        assert!(err.to_string().contains("Missing code_challenge_method"));
    }

    #[test]
    fn rejects_pkce_verifier_shorter_than_rfc_minimum() {
        let result =
            OidcService::verify_pkce_value("short-verifier", Some("S256"), "short-verifier");
        assert!(result
            .expect_err("short verifier should be rejected")
            .to_string()
            .contains("Invalid code verifier"));
    }

    #[test]
    fn rejects_pkce_verifier_with_invalid_charset() {
        let verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._!";
        let result = OidcService::verify_pkce_value(verifier, Some("S256"), verifier);
        assert!(result
            .expect_err("invalid verifier charset should be rejected")
            .to_string()
            .contains("Invalid code verifier"));
    }

    #[test]
    fn argon2_client_secret_round_trips() {
        let hash = hash_client_secret("super-secret-value").expect("hash");
        assert!(hash.starts_with("$argon2"));
        assert!(verify_client_secret_hash(&hash, "super-secret-value"));
        assert!(!verify_client_secret_hash(&hash, "wrong-value"));
    }

    #[test]
    fn legacy_sha256_client_secret_still_verifies() {
        let legacy = format!("{:x}", Sha256::digest(b"legacy-secret"));
        assert!(verify_client_secret_hash(&legacy, "legacy-secret"));
        assert!(!verify_client_secret_hash(&legacy, "other-secret"));
    }

    #[test]
    fn constant_time_eq_matches_semantics_of_plain_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
