use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct Permission {
    pub id: Option<Thing>,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource: String, // 资源类型，如 "user", "role", "auth"
    pub action: String,   // 操作类型，如 "read", "write", "delete"
    pub is_system: bool,  // 系统权限不可删除
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct PermissionResponse {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub is_system: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<Permission> for PermissionResponse {
    fn from(permission: Permission) -> Self {
        Self {
            id: crate::utils::record_id::record_id_key_to_string(&permission.id.unwrap()),
            name: permission.name,
            display_name: permission.display_name,
            description: permission.description,
            resource: permission.resource,
            action: permission.action,
            is_system: permission.is_system,
            created_at: permission.created_at,
            updated_at: permission.updated_at,
        }
    }
}
