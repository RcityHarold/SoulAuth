use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct Role {
    pub id: Option<Thing>,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub is_system: bool, // 系统角色不可删除
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub permissions: Vec<String>, // 权限名称列表
}

impl From<Role> for RoleResponse {
    fn from(role: Role) -> Self {
        Self {
            id: crate::utils::record_id::record_id_key_to_string(&role.id.unwrap()),
            name: role.name,
            display_name: role.display_name,
            description: role.description,
            is_system: role.is_system,
            created_at: role.created_at,
            updated_at: role.updated_at,
            permissions: vec![], // 需要单独查询填充
        }
    }
}
