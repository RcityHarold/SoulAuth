use std::sync::Arc;
use anyhow::{anyhow, Result};
use chrono::Utc;
use rand::{distributions::Alphanumeric, Rng};

use crate::{
    models::oidc_client::{
        OidcClient, CreateOidcClientRequest, OidcClientResponse,
        ClientType, GrantType, ResponseType
    },
    services::{
        database::Database,
        oidc::hash_client_secret,
    },
};

#[derive(Clone)]
pub struct OidcClientService {
    db: Arc<Database>,
}

impl OidcClientService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    // 创建新的 OIDC 客户端
    pub async fn create_client(
        &self,
        request: CreateOidcClientRequest,
        created_by: &str,
    ) -> Result<OidcClientResponse> {
        // 生成客户端ID和密钥
        let client_id = generate_client_id();
        let client_secret = generate_client_secret();
        let client_secret_hash = hash_client_secret(&client_secret)?;

        let now = Utc::now().timestamp();

        let client = OidcClient {
            id: None,
            client_id: client_id.clone(),
            client_secret_hash,
            client_name: request.client_name.clone(),
            client_type: request.client_type.clone(),
            redirect_uris: request.redirect_uris.clone(),
            post_logout_redirect_uris: request.post_logout_redirect_uris.unwrap_or_default(),
            allowed_scopes: request.allowed_scopes.unwrap_or_else(|| {
                vec!["openid".to_string(), "profile".to_string(), "email".to_string()]
            }),
            allowed_grant_types: request.allowed_grant_types.unwrap_or_else(|| {
                vec![GrantType::AuthorizationCode, GrantType::RefreshToken]
            }),
            allowed_response_types: request.allowed_response_types.unwrap_or_else(|| {
                vec![ResponseType::Code]
            }),
            require_pkce: request.require_pkce.unwrap_or(true),
            access_token_lifetime: request.access_token_lifetime.unwrap_or(3600),
            refresh_token_lifetime: request.refresh_token_lifetime.unwrap_or(86400),
            id_token_lifetime: request.id_token_lifetime.unwrap_or(3600),
            is_active: true,
            created_by: created_by.to_string(),
            created_at: now,
            updated_at: now,
        };

        // 保存到数据库
        self.save_client(&client).await?;

        // 返回客户端信息（包含明文密钥，仅此一次）
        Ok(OidcClientResponse {
            client_id,
            client_secret, // 明文密钥仅在创建时返回
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
        })
    }

    // 获取客户端信息
    pub async fn get_client(&self, client_id: &str) -> Result<OidcClient> {
        let query = "SELECT * FROM oidc_client WHERE client_id = $client_id AND is_active = true";
        
        let mut result = self.db.client
            .query(query)
            .bind(("client_id", client_id.to_owned()))
            .await?;

        let client: Option<OidcClient> = result.take(0)?;
        client.ok_or_else(|| anyhow!("Client not found"))
    }

    // 获取客户端列表
    pub async fn list_clients(
        &self,
        limit: Option<i32>,
        offset: Option<i32>,
    ) -> Result<Vec<OidcClientResponse>> {
        let limit = limit.unwrap_or(50);
        let offset = offset.unwrap_or(0);

        let query = "SELECT * FROM oidc_client WHERE is_active = true LIMIT $limit START $offset";
        
        let mut result = self.db.client
            .query(query)
            .bind(("limit", limit))
            .bind(("offset", offset))
            .await?;

        let clients: Vec<OidcClient> = result.take(0)?;
        
        Ok(clients.into_iter().map(|client| OidcClientResponse {
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
        }).collect())
    }

    // 更新客户端
    pub async fn update_client(
        &self,
        client_id: &str,
        request: CreateOidcClientRequest,
    ) -> Result<OidcClientResponse> {
        let mut client = self.get_client(client_id).await?;
        
        // 更新字段
        client.client_name = request.client_name;
        client.client_type = request.client_type;
        client.redirect_uris = request.redirect_uris;
        client.post_logout_redirect_uris = request.post_logout_redirect_uris.unwrap_or_default();
        client.allowed_scopes = request.allowed_scopes.unwrap_or(client.allowed_scopes);
        client.allowed_grant_types = request.allowed_grant_types.unwrap_or(client.allowed_grant_types);
        client.allowed_response_types = request.allowed_response_types.unwrap_or(client.allowed_response_types);
        client.require_pkce = request.require_pkce.unwrap_or(client.require_pkce);
        client.access_token_lifetime = request.access_token_lifetime.unwrap_or(client.access_token_lifetime);
        client.refresh_token_lifetime = request.refresh_token_lifetime.unwrap_or(client.refresh_token_lifetime);
        client.id_token_lifetime = request.id_token_lifetime.unwrap_or(client.id_token_lifetime);
        client.updated_at = Utc::now().timestamp();

        // 保存更新
        self.update_client_in_db(&client).await?;

        Ok(OidcClientResponse {
            client_id: client.client_id,
            client_secret: "***".to_string(),
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
        })
    }

    // 禁用客户端
    pub async fn disable_client(&self, client_id: &str) -> Result<()> {
        let query = "UPDATE oidc_client SET is_active = false, updated_at = time::now() WHERE client_id = $client_id";
        
        self.db.client
            .query(query)
            .bind(("client_id", client_id.to_owned()))
            .await?;

        Ok(())
    }

    // 重新生成客户端密钥
    pub async fn regenerate_client_secret(&self, client_id: &str) -> Result<String> {
        let client_secret = generate_client_secret();
        let client_secret_hash = hash_client_secret(&client_secret)?;

        let query = "UPDATE oidc_client SET client_secret_hash = $hash, updated_at = time::now() WHERE client_id = $client_id";
        
        self.db.client
            .query(query)
            .bind(("hash", client_secret_hash))
            .bind(("client_id", client_id.to_owned()))
            .await?;

        Ok(client_secret)
    }

    // 私有方法：保存客户端到数据库
    async fn save_client(&self, client: &OidcClient) -> Result<()> {
        let query = r#"
            CREATE oidc_client CONTENT {
                client_id: $client_id,
                client_secret_hash: $client_secret_hash,
                client_name: $client_name,
                client_type: $client_type,
                redirect_uris: $redirect_uris,
                post_logout_redirect_uris: $post_logout_redirect_uris,
                allowed_scopes: $allowed_scopes,
                allowed_grant_types: $allowed_grant_types,
                allowed_response_types: $allowed_response_types,
                require_pkce: $require_pkce,
                access_token_lifetime: $access_token_lifetime,
                refresh_token_lifetime: $refresh_token_lifetime,
                id_token_lifetime: $id_token_lifetime,
                is_active: $is_active,
                created_by: $created_by,
                created_at: $created_at,
                updated_at: $updated_at
            }
        "#;

        self.db.client
            .query(query)
            .bind(("client_id", client.client_id.clone()))
            .bind(("client_secret_hash", client.client_secret_hash.clone()))
            .bind(("client_name", client.client_name.clone()))
            .bind(("client_type", client_type_value(&client.client_type)))
            .bind(("redirect_uris", client.redirect_uris.clone()))
            .bind(("post_logout_redirect_uris", client.post_logout_redirect_uris.clone()))
            .bind(("allowed_scopes", client.allowed_scopes.clone()))
            .bind(("allowed_grant_types", grant_type_values(&client.allowed_grant_types)))
            .bind(("allowed_response_types", response_type_values(&client.allowed_response_types)))
            .bind(("require_pkce", client.require_pkce))
            .bind(("access_token_lifetime", client.access_token_lifetime))
            .bind(("refresh_token_lifetime", client.refresh_token_lifetime))
            .bind(("id_token_lifetime", client.id_token_lifetime))
            .bind(("is_active", client.is_active))
            .bind(("created_by", client.created_by.clone()))
            .bind(("created_at", client.created_at))
            .bind(("updated_at", client.updated_at))
            .await?;

        Ok(())
    }

    // 私有方法：更新客户端
    async fn update_client_in_db(&self, client: &OidcClient) -> Result<()> {
        let query = r#"
            UPDATE oidc_client SET
                client_name = $client_name,
                client_type = $client_type,
                redirect_uris = $redirect_uris,
                post_logout_redirect_uris = $post_logout_redirect_uris,
                allowed_scopes = $allowed_scopes,
                allowed_grant_types = $allowed_grant_types,
                allowed_response_types = $allowed_response_types,
                require_pkce = $require_pkce,
                access_token_lifetime = $access_token_lifetime,
                refresh_token_lifetime = $refresh_token_lifetime,
                id_token_lifetime = $id_token_lifetime,
                updated_at = $updated_at
            WHERE client_id = $client_id
        "#;

        self.db.client
            .query(query)
            .bind(("client_id", client.client_id.clone()))
            .bind(("client_name", client.client_name.clone()))
            .bind(("client_type", client_type_value(&client.client_type)))
            .bind(("redirect_uris", client.redirect_uris.clone()))
            .bind(("post_logout_redirect_uris", client.post_logout_redirect_uris.clone()))
            .bind(("allowed_scopes", client.allowed_scopes.clone()))
            .bind(("allowed_grant_types", grant_type_values(&client.allowed_grant_types)))
            .bind(("allowed_response_types", response_type_values(&client.allowed_response_types)))
            .bind(("require_pkce", client.require_pkce))
            .bind(("access_token_lifetime", client.access_token_lifetime))
            .bind(("refresh_token_lifetime", client.refresh_token_lifetime))
            .bind(("id_token_lifetime", client.id_token_lifetime))
            .bind(("updated_at", client.updated_at))
            .await?;

        Ok(())
    }
}

// 辅助函数
fn generate_client_id() -> String {
    let timestamp = Utc::now().timestamp_millis();
    let random: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    format!("client_{}{}", timestamp, random)
}

fn generate_client_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn client_type_value(value: &ClientType) -> &'static str {
    match value {
        ClientType::Public => "public",
        ClientType::Confidential => "confidential",
    }
}

fn grant_type_values(values: &[GrantType]) -> Vec<&'static str> {
    values
        .iter()
        .map(|value| match value {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::RefreshToken => "refresh_token",
            GrantType::ClientCredentials => "client_credentials",
        })
        .collect()
}

fn response_type_values(values: &[ResponseType]) -> Vec<&'static str> {
    values
        .iter()
        .map(|value| match value {
            ResponseType::Code => "code",
            ResponseType::IdToken => "id_token",
            ResponseType::CodeIdToken => "code id_token",
        })
        .collect()
}
