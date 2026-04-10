use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct UserRole {
    pub id: Option<Thing>,
    pub user_id: Thing,
    pub role_id: Thing,
    pub assigned_at: i64,
    pub assigned_by: Thing, // 分配者的用户ID
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct RolePermission {
    pub id: Option<Thing>,
    pub role_id: Thing,
    pub permission_id: Thing,
    pub granted_at: i64,
    pub granted_by: Thing, // 授权者的用户ID
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssignRoleRequest {
    pub role_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveRoleRequest {
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
