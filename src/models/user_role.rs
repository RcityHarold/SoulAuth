use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserRole {
    pub id: Option<Thing>,
    pub user_id: Thing,
    pub role_id: Thing,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Thing, // 分配者的用户ID
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RolePermission {
    pub id: Option<Thing>,
    pub role_id: Thing,
    pub permission_id: Thing,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub granted_at: DateTime<Utc>,
    pub granted_by: Thing, // 授权者的用户ID
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    pub user_id: String,
    pub role_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveRoleRequest {
    pub user_id: String,
    pub role_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssignPermissionToRoleRequest {
    pub role_name: String,
    pub permission_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemovePermissionFromRoleRequest {
    pub role_name: String,
    pub permission_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRoleResponse {
    pub user_id: String,
    pub roles: Vec<RoleWithPermissions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoleWithPermissions {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub assigned_at: DateTime<Utc>,
}
