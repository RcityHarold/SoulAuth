use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct UserActivity {
    pub id: Option<Thing>,
    pub user_id: Thing,
    pub action: String,
    pub category: ActivityCategory,
    pub ip_address: String,
    pub user_agent: String,
    pub details: serde_json::Value,
    pub status: ActivityStatus,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub enum ActivityCategory {
    Authentication,
    Profile,
    Security,
    Permissions,
    Data,
    System,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub enum ActivityStatus {
    Success,
    Failed,
    Warning,
    Info,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserActivityResponse {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub category: ActivityCategory,
    pub ip_address: String,
    pub user_agent: String,
    pub details: serde_json::Value,
    pub status: ActivityStatus,
    pub timestamp: DateTime<Utc>,
}

impl From<UserActivity> for UserActivityResponse {
    fn from(activity: UserActivity) -> Self {
        Self {
            id: activity.id
                .map(|id| crate::utils::record_id::record_id_key_to_string(&id))
                .unwrap_or_default(),
            user_id: crate::utils::record_id::record_id_key_to_string(&activity.user_id),
            action: activity.action,
            category: activity.category,
            ip_address: activity.ip_address,
            user_agent: activity.user_agent,
            details: activity.details,
            status: activity.status,
            timestamp: activity.timestamp,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityLogRequest {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub category: Option<ActivityCategory>,
    pub status: Option<ActivityStatus>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityLogResponse {
    pub activities: Vec<UserActivityResponse>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
    pub total_pages: u32,
}
