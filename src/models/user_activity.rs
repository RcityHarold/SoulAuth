use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

/// 审计事件。
///
/// `timestamp` 用 Unix 秒（i64），与 `schema.sql` 的 `TYPE number` 以及所有
/// 审计查询里的 `timestamp >= <秒>` 对齐；以前这里是 `DateTime<Utc>`，
/// 写进 number 列会被 SCHEMAFULL 拒绝，等于审计事件根本落不了库。
///
/// `user_id` 是可选的：登录失败、限流触发这类事件未必对应一个已存在的用户。
#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct UserActivity {
    pub id: Option<Thing>,
    pub user_id: Option<Thing>,
    pub action: String,
    pub category: ActivityCategory,
    pub ip_address: String,
    pub user_agent: String,
    pub details: serde_json::Value,
    pub status: ActivityStatus,
    pub timestamp: i64,
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
            user_id: activity
                .user_id
                .as_ref()
                .map(crate::utils::record_id::record_id_key_to_string)
                .unwrap_or_default(),
            action: activity.action,
            category: activity.category,
            ip_address: activity.ip_address,
            user_agent: activity.user_agent,
            details: activity.details,
            status: activity.status,
            timestamp: chrono::DateTime::<Utc>::from_timestamp(activity.timestamp, 0)
                .unwrap_or_else(Utc::now),
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
