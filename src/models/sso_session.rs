use serde::{Deserialize, Serialize};
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct SsoSession {
    pub id: Option<String>,
    pub session_id: String,
    pub user_id: String,
    pub client_sessions: Vec<ClientSession>,
    pub created_at: i64,
    pub last_accessed_at: i64,
    pub expires_at: i64,
    pub ip_address: String,
    pub user_agent: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct ClientSession {
    pub client_id: String,
    pub session_id: String,
    pub created_at: i64,
    pub last_accessed_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSsoSessionRequest {
    pub user_id: String,
    pub client_id: String,
    pub ip_address: String,
    pub user_agent: String,
    pub expires_in: Option<i64>, // 秒数，默认8小时
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SsoSessionResponse {
    pub session_id: String,
    pub user_id: String,
    pub client_sessions: Vec<ClientSession>,
    pub created_at: i64,
    pub last_accessed_at: i64,
    pub expires_at: i64,
    pub is_active: bool,
}

impl SsoSession {
    pub fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.expires_at < now
    }

    pub fn add_client_session(&mut self, client_id: String) {
        let now = chrono::Utc::now().timestamp();
        
        // 检查是否已存在该客户端会话
        if let Some(existing) = self.client_sessions.iter_mut().find(|cs| cs.client_id == client_id) {
            existing.last_accessed_at = now;
        } else {
            self.client_sessions.push(ClientSession {
                client_id,
                session_id: uuid::Uuid::new_v4().to_string(),
                created_at: now,
                last_accessed_at: now,
            });
        }
        
        self.last_accessed_at = now;
    }

    pub fn remove_client_session(&mut self, client_id: &str) {
        self.client_sessions.retain(|cs| cs.client_id != client_id);
        self.last_accessed_at = chrono::Utc::now().timestamp();
    }

    pub fn has_client_session(&self, client_id: &str) -> bool {
        self.client_sessions.iter().any(|cs| cs.client_id == client_id)
    }
}
