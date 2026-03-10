use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct Session {
    pub id: Option<Thing>,
    pub user_id: Thing,
    pub token: String,
    pub expires_at: i64, // Unix timestamp
    pub created_at: i64, // Unix timestamp
    pub user_agent: String,
    pub ip_address: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub user_agent: String,
    pub ip_address: String,
    pub is_current: bool,
}
