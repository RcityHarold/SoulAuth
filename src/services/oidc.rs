use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use crate::{
    config::Config,
    models::{
        oidc_client::{OidcClient, ClientType, GrantType, ResponseType},
        oidc_token::{
            OidcAuthorizationCode, OidcAccessToken, OidcRefreshToken,
            TokenResponse, TokenRequest, AuthorizeRequest, IdTokenClaims, UserInfoResponse
        },
        sso_session::SsoSession,
        user::User,
    },
    services::database::Database,
    error::AuthError,
};

#[derive(Clone)]
pub struct OidcService {
    db: Arc<Database>,
    config: Config,
    signing_key: EncodingKey,
    verification_key: DecodingKey,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    pub use_: String,
    pub alg: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

impl OidcService {
    pub fn new(db: Arc<Database>, config: Config) -> Result<Self> {
        let signing_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let verification_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Ok(Self {
            db,
            config,
            signing_key,
            verification_key,
        })
    }

    // OIDC Discovery Endpoint
    pub fn get_configuration(&self) -> OidcConfiguration {
        let base_url = &self.config.app_url;
        
        OidcConfiguration {
            issuer: base_url.clone(),
            authorization_endpoint: format!("{}/api/oidc/authorize", base_url),
            token_endpoint: format!("{}/api/oidc/token", base_url),
            userinfo_endpoint: format!("{}/api/oidc/userinfo", base_url),
            jwks_uri: format!("{}/api/oidc/jwks", base_url),
            end_session_endpoint: format!("{}/api/oidc/logout", base_url),
            response_types_supported: vec!["code".to_string(), "id_token".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["HS256".to_string()],
            scopes_supported: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_post".to_string(),
                "client_secret_basic".to_string(),
            ],
            code_challenge_methods_supported: vec!["S256".to_string(), "plain".to_string()],
        }
    }

    // 授权码流程 - 生成授权码
    pub async fn create_authorization_code(
        &self,
        request: &AuthorizeRequest,
        user_id: &str,
    ) -> Result<String> {
        // 验证客户端
        let client = self.get_client(&request.client_id).await?;
        if !client.is_active {
            return Err(anyhow!("Client is not active"));
        }

        // 验证重定向URI
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(anyhow!("Invalid redirect URI"));
        }

        // 验证响应类型
        let response_types: Vec<ResponseType> = request.response_type
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

        // 生成授权码
        let code = generate_random_string(32);
        let expires_at = Utc::now().timestamp() + 600; // 10分钟过期
        let scope = request.scope.clone().unwrap_or_else(|| "openid".to_string());

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

    // 令牌端点 - 交换授权码获取令牌
    pub async fn exchange_code_for_tokens(
        &self,
        request: &TokenRequest,
    ) -> Result<TokenResponse> {
        match request.grant_type.as_str() {
            "authorization_code" => self.handle_authorization_code_grant(request).await,
            "refresh_token" => self.handle_refresh_token_grant(request).await,
            _ => Err(anyhow!("Unsupported grant type")),
        }
    }

    async fn handle_authorization_code_grant(
        &self,
        request: &TokenRequest,
    ) -> Result<TokenResponse> {
        let code = request.code.as_ref().ok_or_else(|| anyhow!("Missing authorization code"))?;
        let redirect_uri = request.redirect_uri.as_ref().ok_or_else(|| anyhow!("Missing redirect URI"))?;

        // 验证客户端
        let client = self.get_client(&request.client_id).await?;
        if let Some(client_secret) = &request.client_secret {
            if !self.verify_client_secret(&client, client_secret)? {
                return Err(anyhow!("Invalid client credentials"));
            }
        } else if client.client_type == ClientType::Confidential {
            return Err(anyhow!("Client secret required for confidential clients"));
        }

        // 获取并验证授权码
        let mut auth_code = self.get_authorization_code(code).await?;
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
            let code_verifier = request.code_verifier.as_ref()
                .ok_or_else(|| anyhow!("Code verifier required"))?;
            
            if !self.verify_pkce(code_challenge, &auth_code.code_challenge_method, code_verifier)? {
                return Err(anyhow!("Invalid code verifier"));
            }
        }

        // 标记授权码为已使用
        auth_code.used = true;
        self.update_authorization_code(&auth_code).await?;

        // 生成令牌
        self.generate_tokens(&client, &auth_code.user_id, &auth_code.scope, auth_code.nonce.as_deref()).await
    }

    async fn handle_refresh_token_grant(
        &self,
        request: &TokenRequest,
    ) -> Result<TokenResponse> {
        let refresh_token = request.refresh_token.as_ref()
            .ok_or_else(|| anyhow!("Missing refresh token"))?;

        // 获取并验证刷新令牌
        let mut stored_refresh_token = self.get_refresh_token(refresh_token).await?;
        if stored_refresh_token.used {
            return Err(anyhow!("Refresh token already used"));
        }
        if stored_refresh_token.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Refresh token expired"));
        }
        if stored_refresh_token.client_id != request.client_id {
            return Err(anyhow!("Refresh token was not issued to this client"));
        }

        // 验证客户端
        let client = self.get_client(&request.client_id).await?;
        if let Some(client_secret) = &request.client_secret {
            if !self.verify_client_secret(&client, client_secret)? {
                return Err(anyhow!("Invalid client credentials"));
            }
        }

        // 标记旧的刷新令牌为已使用
        stored_refresh_token.used = true;
        self.update_refresh_token(&stored_refresh_token).await?;

        // 使旧的访问令牌失效
        self.revoke_access_token(&stored_refresh_token.access_token).await?;

        // 生成新的令牌
        let scope = request.scope.as_deref().unwrap_or(&stored_refresh_token.scope);
        self.generate_tokens(&client, &stored_refresh_token.user_id, scope, None).await
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
        
        self.save_access_token(&oidc_access_token).await?;

        // 生成刷新令牌
        let refresh_token = if client.allowed_grant_types.contains(&GrantType::RefreshToken) {
            let token = generate_random_string(32);
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
            
            self.save_refresh_token(&oidc_refresh_token).await?;
            Some(token)
        } else {
            None
        };

        // 生成 ID 令牌（如果 scope 包含 openid）
        let id_token = if scope.contains("openid") {
            let user = self.get_user_by_id(user_id).await?;
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
            iss: self.config.app_url.clone(),
            sub: crate::utils::record_id::record_id_key_to_string(&user.id.as_ref().unwrap()),
            aud: client.client_id.clone(),
            exp,
            iat: now,
            auth_time: user.last_login_at.unwrap_or(now),
            nonce: nonce.map(|n| n.to_string()),
            email: Some(user.email.clone()),
            email_verified: Some(user.is_email_verified),
            name: None, // 需要从用户档案获取
            preferred_username: Some(user.email.clone()),
            profile: None,
            picture: None,
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.signing_key)
            .map_err(|e| anyhow!("Failed to generate ID token: {}", e))
    }

    // UserInfo 端点
    pub async fn get_userinfo(&self, access_token: &str) -> Result<UserInfoResponse> {
        let token = self.get_access_token(access_token).await?;
        if token.expires_at < Utc::now().timestamp() {
            return Err(anyhow!("Access token expired"));
        }

        let user = self.get_user_by_id(&token.user_id).await?;
        
        Ok(UserInfoResponse {
            sub: crate::utils::record_id::record_id_key_to_string(&user.id.unwrap()),
            email: Some(user.email.clone()),
            email_verified: Some(user.is_email_verified),
            name: None, // 需要从用户档案获取
            preferred_username: Some(user.email),
            profile: None,
            picture: None,
            updated_at: Some(user.updated_at),
        })
    }

    // 辅助方法
    fn verify_client_secret(&self, client: &OidcClient, provided_secret: &str) -> Result<bool> {
        // 这里应该使用安全的密码验证方法，比如 Argon2
        // 暂时使用简单的哈希比较
        let provided_hash = format!("{:x}", Sha256::digest(provided_secret.as_bytes()));
        Ok(provided_hash == client.client_secret_hash)
    }

    fn verify_pkce(
        &self,
        code_challenge: &str,
        method: &Option<String>,
        code_verifier: &str,
    ) -> Result<bool> {
        match method.as_deref().unwrap_or("plain") {
            "S256" => {
                let hash = Sha256::digest(code_verifier.as_bytes());
                let encoded = general_purpose::URL_SAFE_NO_PAD.encode(hash);
                Ok(encoded == code_challenge)
            }
            "plain" => Ok(code_verifier == code_challenge),
            _ => Err(anyhow!("Unsupported code challenge method")),
        }
    }

    // 数据库操作方法（需要实现）
    async fn get_client(&self, client_id: &str) -> Result<OidcClient> {
        // TODO: 实现数据库查询
        Err(anyhow!("Not implemented"))
    }

    async fn get_user_by_id(&self, user_id: &str) -> Result<User> {
        // TODO: 实现数据库查询
        Err(anyhow!("Not implemented"))
    }

    async fn save_authorization_code(&self, _code: &OidcAuthorizationCode) -> Result<()> {
        // TODO: 实现数据库保存
        Ok(())
    }

    async fn get_authorization_code(&self, _code: &str) -> Result<OidcAuthorizationCode> {
        // TODO: 实现数据库查询
        Err(anyhow!("Not implemented"))
    }

    async fn update_authorization_code(&self, _code: &OidcAuthorizationCode) -> Result<()> {
        // TODO: 实现数据库更新
        Ok(())
    }

    async fn save_access_token(&self, _token: &OidcAccessToken) -> Result<()> {
        // TODO: 实现数据库保存
        Ok(())
    }

    async fn get_access_token(&self, _token: &str) -> Result<OidcAccessToken> {
        // TODO: 实现数据库查询
        Err(anyhow!("Not implemented"))
    }

    async fn revoke_access_token(&self, _token: &str) -> Result<()> {
        // TODO: 实现令牌撤销
        Ok(())
    }

    async fn save_refresh_token(&self, _token: &OidcRefreshToken) -> Result<()> {
        // TODO: 实现数据库保存
        Ok(())
    }

    async fn get_refresh_token(&self, _token: &str) -> Result<OidcRefreshToken> {
        // TODO: 实现数据库查询
        Err(anyhow!("Not implemented"))
    }

    async fn update_refresh_token(&self, _token: &OidcRefreshToken) -> Result<()> {
        // TODO: 实现数据库更新
        Ok(())
    }
}

fn generate_random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}