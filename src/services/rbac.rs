use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tracing::{error, info, warn};
use surrealdb_types::SurrealValue;

use crate::{
    error::AuthError,
    models::{
        role::{Role, CreateRoleRequest, UpdateRoleRequest, RoleResponse},
        permission::{Permission, CreatePermissionRequest, UpdatePermissionRequest, PermissionResponse},
        user_role::{UserRole, RolePermission, UserRoleResponse, RoleWithPermissions},
        user::User,
    },
    services::database::Database,
};

pub struct RBACService {
    db: Arc<Database>,
}

impl RBACService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    // 角色管理
    pub async fn create_role(&self, request: CreateRoleRequest, created_by: &User) -> Result<RoleResponse, AuthError> {
        // 检查角色名是否已存在
        if self.get_role_by_name(&request.name).await?.is_some() {
            return Err(AuthError::ValidationError("Role name already exists".to_string()));
        }

        let now = Utc::now().timestamp();
        let role = Role {
            id: None,
            name: request.name.clone(),
            display_name: request.display_name.clone(),
            description: request.description.clone(),
            is_system: false,
            created_at: now,
            updated_at: now,
        };

        let query = "CREATE role CONTENT $role";
        let mut response = self.db.client
            .query(query)
            .bind(("role", role.clone()))
            .await
            .map_err(|e| {
                error!("Failed to create role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created_role: Vec<Role> = response.take(0).map_err(|e| {
            error!("Failed to parse created role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created_role.is_empty() {
            return Err(AuthError::DatabaseError("Failed to create role".to_string()));
        }

        info!("Role '{}' created by user '{}'", request.name, created_by.email);
        Ok(created_role[0].clone().into())
    }

    pub async fn get_role_by_name(&self, name: &str) -> Result<Option<Role>, AuthError> {
        let query = "SELECT * FROM role WHERE name = $name";
        let mut response = self
            .db
            .client
            .query(query)
            .bind(("name", name.to_owned()))
            .await
            .map_err(|e| {
                error!("Failed to get role by name: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let roles: Vec<Role> = response.take(0).map_err(|e| {
            error!("Failed to parse role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(roles.into_iter().next())
    }

    pub async fn get_role_by_id(&self, role_id: &str) -> Result<Option<Role>, AuthError> {
        let query = format!("SELECT * FROM role:{}", role_id);
        let mut response = self.db.client
            .query(&query)
            .await
            .map_err(|e| {
                error!("Failed to get role by id: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let roles: Vec<Role> = response.take(0).map_err(|e| {
            error!("Failed to parse role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(roles.into_iter().next())
    }

    pub async fn update_role(&self, role_name: &str, request: UpdateRoleRequest, updated_by: &User) -> Result<RoleResponse, AuthError> {
        let role = self.get_role_by_name(role_name).await?
            .ok_or_else(|| AuthError::NotFound("Role not found".to_string()))?;

        if role.is_system {
            return Err(AuthError::ValidationError("Cannot update system role".to_string()));
        }

        let role_id = role.id.ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;

        let mut updates = Vec::new();
        if let Some(display_name) = &request.display_name {
            updates.push(format!("display_name = '{}'", display_name));
        }
        if let Some(description) = &request.description {
            updates.push(format!("description = '{}'", description));
        }
        updates.push(format!("updated_at = {}", Utc::now().timestamp()));

        if updates.is_empty() {
            return Err(AuthError::ValidationError("No fields to update".to_string()));
        }

        let role_key = crate::utils::record_id::record_id_key_to_string(&role_id);
        let query = format!("UPDATE role:{} SET {}", role_key, updates.join(", "));
        let mut response = self
            .db
            .client
            .query(&query)
            .await
            .map_err(|e| {
                error!("Failed to update role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let updated_role: Vec<Role> = response.take(0).map_err(|e| {
            error!("Failed to parse updated role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if updated_role.is_empty() {
            return Err(AuthError::DatabaseError("Failed to update role".to_string()));
        }

        info!("Role '{}' updated by user '{}'", role_name, updated_by.email);
        Ok(updated_role[0].clone().into())
    }

    pub async fn delete_role(&self, role_name: &str, deleted_by: &User) -> Result<(), AuthError> {
        let role = self.get_role_by_name(role_name).await?
            .ok_or_else(|| AuthError::NotFound("Role not found".to_string()))?;

        if role.is_system {
            return Err(AuthError::ValidationError("Cannot delete system role".to_string()));
        }

        let role_id = role.id.ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;

        // 检查是否有用户使用此角色
        let user_count_query = "SELECT count() as count FROM user_role WHERE role_id = $role_id GROUP ALL";
        let mut response = self.db.client
            .query(user_count_query)
            .bind(("role_id", role_id.clone()))
            .await
            .map_err(|e| {
                error!("Failed to check role usage: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let count_result: Vec<serde_json::Value> = response.take(0).map_err(|e| {
            error!("Failed to parse count result: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if !count_result.is_empty() {
            if let Some(count) = count_result[0].get("count") {
                if count.as_u64().unwrap_or(0) > 0 {
                    return Err(AuthError::ValidationError("Cannot delete role that is assigned to users".to_string()));
                }
            }
        }

        // 删除角色的权限关联
        let delete_permissions_query = "DELETE FROM role_permission WHERE role_id = $role_id";
        self.db.client
            .query(delete_permissions_query)
            .bind(("role_id", role_id.clone()))
            .await
            .map_err(|e| {
                error!("Failed to delete role permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        // 删除角色
        let role_key = crate::utils::record_id::record_id_key_to_string(&role_id);
        let delete_query = format!("DELETE role:{}", role_key);
        self.db.client
            .query(&delete_query)
            .await
            .map_err(|e| {
                error!("Failed to delete role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        info!("Role '{}' deleted by user '{}'", role_name, deleted_by.email);
        Ok(())
    }

    pub async fn list_roles(&self, page: Option<u32>, limit: Option<u32>) -> Result<Vec<RoleResponse>, AuthError> {
        let page = page.unwrap_or(1);
        let limit = limit.unwrap_or(50);
        let offset = (page - 1) * limit;

        let query = format!("SELECT * FROM role ORDER BY created_at DESC LIMIT {} START {}", limit, offset);
        let mut response = self
            .db
            .client
            .query(&query)
            .await
            .map_err(|e| {
                error!("Failed to list roles: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let roles: Vec<Role> = response.take(0).map_err(|e| {
            error!("Failed to parse roles: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(roles.into_iter().map(|role| role.into()).collect())
    }

    // 权限管理
    pub async fn create_permission(&self, request: CreatePermissionRequest, created_by: &User) -> Result<PermissionResponse, AuthError> {
        // 检查权限名是否已存在
        if self.get_permission_by_name(&request.name).await?.is_some() {
            return Err(AuthError::ValidationError("Permission name already exists".to_string()));
        }

        let now = Utc::now().timestamp();
        let permission = Permission {
            id: None,
            name: request.name.clone(),
            display_name: request.display_name.clone(),
            description: request.description.clone(),
            resource: request.resource.clone(),
            action: request.action.clone(),
            is_system: false,
            created_at: now,
            updated_at: now,
        };

        let query = "CREATE permission CONTENT $permission";
        let mut response = self.db.client
            .query(query)
            .bind(("permission", permission.clone()))
            .await
            .map_err(|e| {
                error!("Failed to create permission: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created_permission: Vec<Permission> = response.take(0).map_err(|e| {
            error!("Failed to parse created permission: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created_permission.is_empty() {
            return Err(AuthError::DatabaseError("Failed to create permission".to_string()));
        }

        info!("Permission '{}' created by user '{}'", request.name, created_by.email);
        Ok(created_permission[0].clone().into())
    }

    pub async fn get_permission_by_name(&self, name: &str) -> Result<Option<Permission>, AuthError> {
        let query = "SELECT * FROM permission WHERE name = $name";
        let mut response = self.db.client
            .query(query)
            .bind(("name", name.to_owned()))
            .await
            .map_err(|e| {
                error!("Failed to get permission by name: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permissions: Vec<Permission> = response.take(0).map_err(|e| {
            error!("Failed to parse permission: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(permissions.into_iter().next())
    }

    pub async fn list_permissions(&self, page: Option<u32>, limit: Option<u32>) -> Result<Vec<PermissionResponse>, AuthError> {
        let page = page.unwrap_or(1);
        let limit = limit.unwrap_or(50);
        let offset = (page - 1) * limit;

        let query = format!("SELECT * FROM permission ORDER BY resource, action LIMIT {} START {}", limit, offset);
        let mut response = self.db.client
            .query(&query)
            .await
            .map_err(|e| {
                error!("Failed to list permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permissions: Vec<Permission> = response.take(0).map_err(|e| {
            error!("Failed to parse permissions: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        Ok(permissions.into_iter().map(|permission| permission.into()).collect())
    }


    // 用户角色分配
    pub async fn assign_role_to_user(&self, user_id: &str, role_name: &str, assigned_by: &User) -> Result<(), AuthError> {
        let role = self.get_role_by_name(role_name).await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;

        let role_id = role.id.ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
        let user_thing = surrealdb::types::RecordId::new("user", user_id);
        let assigned_by_thing = assigned_by.id.as_ref()
            .ok_or_else(|| AuthError::DatabaseError("Assigned by user ID not found".to_string()))?;

        // 检查用户是否已经有此角色
        let check_query = "SELECT * FROM user_role WHERE user_id = $user_id AND role_id = $role_id";
        let mut response = self.db.client
            .query(check_query)
            .bind(("user_id", user_thing.clone()))
            .bind(("role_id", role_id.clone()))
            .await
            .map_err(|e| {
                error!("Failed to check user role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let existing: Vec<UserRole> = response.take(0).map_err(|e| {
            error!("Failed to parse user role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if !existing.is_empty() {
            return Err(AuthError::ValidationError("User already has this role".to_string()));
        }

        let user_role = UserRole {
            id: None,
            user_id: user_thing,
            role_id,
            assigned_at: Utc::now().timestamp(),
            assigned_by: assigned_by_thing.clone(),
        };

        let query = "CREATE user_role CONTENT $user_role";
        let mut create_response = self.db.client
            .query(query)
            .bind(("user_role", user_role.clone()))
            .await
            .map_err(|e| {
                error!("Failed to assign role to user: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created: Vec<UserRole> = create_response.take(0).map_err(|e| {
            error!("Failed to parse created user role: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created.is_empty() {
            return Err(AuthError::DatabaseError("Failed to persist user role".to_string()));
        }

        info!("Role '{}' assigned to user '{}' by '{}'", role_name, user_id, assigned_by.email);
        Ok(())
    }

    pub async fn remove_role_from_user(&self, user_id: &str, role_name: &str, removed_by: &User) -> Result<(), AuthError> {
        let role = self.get_role_by_name(role_name).await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;

        let role_id = role.id.ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
        let user_thing = surrealdb::types::RecordId::new("user", user_id);

        let delete_query = "DELETE FROM user_role WHERE user_id = $user_id AND role_id = $role_id";
        self.db.client
            .query(delete_query)
            .bind(("user_id", user_thing.clone()))
            .bind(("role_id", role_id.clone()))
            .await
            .map_err(|e| {
                error!("Failed to remove role from user: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        info!("Role '{}' removed from user '{}' by '{}'", role_name, user_id, removed_by.email);
        Ok(())
    }

    pub async fn get_user_roles(&self, user_id: &str) -> Result<UserRoleResponse, AuthError> {
        #[derive(Debug, serde::Deserialize, SurrealValue)]
        struct UserRoleRow {
            role_id: String,
            assigned_at: Option<i64>,
        }

        let user_id_bracketed = format!("user:⟨{}⟩", user_id);
        let user_id_plain = format!("user:{}", user_id);

        let query = r#"
            SELECT string::replace(type::string(role_id), 'role:', '') as role_id, assigned_at
            FROM user_role
            WHERE type::string(user_id) IN [$user_id_bracketed, $user_id_plain]
        "#;

        let mut response = self.db.client
            .query(query)
            .bind(("user_id_bracketed", user_id_bracketed))
            .bind(("user_id_plain", user_id_plain))
            .await
            .map_err(|e| {
                error!("Failed to get user roles: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let role_data: Vec<UserRoleRow> = response.take(0).map_err(|e| {
            error!("Failed to parse user roles: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if role_data.is_empty() {
            return Ok(UserRoleResponse {
                user_id: user_id.to_string(),
                roles: Vec::new(),
            });
        }

        let mut assigned_at_map: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        let mut role_ids: Vec<surrealdb::types::RecordId> = Vec::new();
        for data in &role_data {
            let role_id_str = data.role_id.trim();
            if role_id_str.is_empty() {
                continue;
            }
            let assigned_at = data.assigned_at.unwrap_or(0);

            assigned_at_map.insert(role_id_str.to_string(), assigned_at);
            role_ids.push(surrealdb::types::RecordId::new("role", role_id_str));
        }

        if role_ids.is_empty() {
            return Ok(UserRoleResponse {
                user_id: user_id.to_string(),
                roles: Vec::new(),
            });
        }

        let role_query = "SELECT * FROM role WHERE id IN $role_ids";
        let mut role_response = self.db.client
            .query(role_query)
            .bind(("role_ids", role_ids))
            .await
            .map_err(|e| {
                error!("Failed to get roles: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let roles: Vec<Role> = role_response.take(0).map_err(|e| {
            error!("Failed to parse roles: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        let mut roles_with_permissions = Vec::new();
        for role in roles {
            let role_id = role.id.clone().ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
            let role_id_str = crate::utils::record_id::record_id_key_to_string(&role_id);
            let role_name = role.name.clone();
            let permissions = self.get_role_permissions(&role_name).await?;

            let assigned_at = assigned_at_map.get(role_id_str.as_str()).copied().unwrap_or(0);
            roles_with_permissions.push(RoleWithPermissions {
                id: role_id_str,
                name: role_name,
                display_name: role.display_name.clone(),
                description: role.description.clone(),
                permissions,
                assigned_at: chrono::DateTime::from_timestamp(assigned_at, 0).unwrap_or_default(),
            });
        }

        Ok(UserRoleResponse {
            user_id: user_id.to_string(),
            roles: roles_with_permissions,
        })
    }

    pub async fn get_role_permissions(&self, role_name: &str) -> Result<Vec<String>, AuthError> {
        let role = self.get_role_by_name(role_name).await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;

        let role_id = role.id.ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;

        // SurrealDB 2.x does not support JOIN; use subqueries
        let ids_query = "SELECT VALUE permission_id FROM role_permission WHERE role_id = $role_id";
        let mut ids_response = self.db.client
            .query(ids_query)
            .bind(("role_id", role_id.clone()))
            .await
            .map_err(|e| {
                error!("Failed to get role permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permission_ids: Vec<surrealdb::types::RecordId> = ids_response.take(0).map_err(|e| {
            error!("Failed to parse role permission ids: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if permission_ids.is_empty() {
            return Ok(Vec::new());
        }

        let names_query = "SELECT name FROM permission WHERE id IN $permission_ids";
        let mut names_response = self.db.client
            .query(names_query)
            .bind(("permission_ids", permission_ids))
            .await
            .map_err(|e| {
                error!("Failed to get role permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permission_data: Vec<serde_json::Value> = names_response.take(0).map_err(|e| {
            error!("Failed to parse role permissions: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        let permissions = permission_data
            .into_iter()
            .map(|data| data["name"].as_str().unwrap_or("").to_string())
            .filter(|name| !name.is_empty())
            .collect();

        Ok(permissions)
    }

    pub async fn assign_permission_to_role(&self, role_name: &str, permission_name: &str, granted_by: &User) -> Result<(), AuthError> {
        let role = self.get_role_by_name(role_name).await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;
        
        let permission = self.get_permission_by_name(permission_name).await?
            .ok_or_else(|| AuthError::NotFound(format!("Permission '{}' not found", permission_name)))?;

        let role_id = role.id.ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
        let permission_id = permission.id.ok_or_else(|| AuthError::DatabaseError("Permission ID not found".to_string()))?;
        let granted_by_thing = granted_by.id.as_ref()
            .ok_or_else(|| AuthError::DatabaseError("Granted by user ID not found".to_string()))?;

        // 检查是否已经分配
        let check_query = "SELECT * FROM role_permission WHERE role_id = $role_id AND permission_id = $permission_id";
        let mut response = self.db.client
            .query(check_query)
            .bind(("role_id", role_id.clone()))
            .bind(("permission_id", permission_id.clone()))
            .await
            .map_err(|e| {
                error!("Failed to check role permission: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let existing: Vec<RolePermission> = response.take(0).map_err(|e| {
            error!("Failed to parse role permission: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if !existing.is_empty() {
            return Err(AuthError::ValidationError("Role already has this permission".to_string()));
        }

        let role_permission = RolePermission {
            id: None,
            role_id,
            permission_id,
            granted_at: Utc::now().timestamp(),
            granted_by: granted_by_thing.clone(),
        };

        let query = "CREATE role_permission CONTENT $role_permission";
        let mut create_response = self.db.client
            .query(query)
            .bind(("role_permission", role_permission.clone()))
            .await
            .map_err(|e| {
                error!("Failed to assign permission to role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created: Vec<RolePermission> = create_response.take(0).map_err(|e| {
            error!("Failed to parse created role permission: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created.is_empty() {
            return Err(AuthError::DatabaseError("Failed to persist role permission".to_string()));
        }

        info!("Permission '{}' assigned to role '{}' by '{}'", permission_name, role_name, granted_by.email);
        Ok(())
    }

    pub async fn remove_permission_from_role(&self, role_name: &str, permission_name: &str, removed_by: &User) -> Result<(), AuthError> {
        let role = self.get_role_by_name(role_name).await?
            .ok_or_else(|| AuthError::NotFound(format!("Role '{}' not found", role_name)))?;
        
        let permission = self.get_permission_by_name(permission_name).await?
            .ok_or_else(|| AuthError::NotFound(format!("Permission '{}' not found", permission_name)))?;

        let role_id = role.id.ok_or_else(|| AuthError::DatabaseError("Role ID not found".to_string()))?;
        let permission_id = permission.id.ok_or_else(|| AuthError::DatabaseError("Permission ID not found".to_string()))?;

        let delete_query = "DELETE FROM role_permission WHERE role_id = $role_id AND permission_id = $permission_id";
        self.db.client
            .query(delete_query)
            .bind(("role_id", role_id.clone()))
            .bind(("permission_id", permission_id.clone()))
            .await
            .map_err(|e| {
                error!("Failed to remove permission from role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        info!("Permission '{}' removed from role '{}' by '{}'", permission_name, role_name, removed_by.email);
        Ok(())
    }

    // 权限检查
    pub async fn check_user_permission(&self, user_id: &str, permission_name: &str) -> Result<bool, AuthError> {
        let user_id_bracketed = format!("user:⟨{}⟩", user_id);
        let user_id_plain = format!("user:{}", user_id);
        let user_id_quoted = format!("user:`{}`", user_id);
        
        let query = r#"
            SELECT count() as count
            FROM role_permission
            WHERE role_id IN (
                SELECT VALUE role_id
                FROM user_role
                WHERE type::string(user_id) IN [$user_id_bracketed, $user_id_plain, $user_id_quoted]
            )
              AND permission_id IN (SELECT VALUE id FROM permission WHERE name = $permission_name)
            GROUP ALL
        "#;

        let mut response = self.db.client
            .query(query)
            .bind(("user_id_bracketed", user_id_bracketed))
            .bind(("user_id_plain", user_id_plain))
            .bind(("user_id_quoted", user_id_quoted))
            .bind(("permission_name", permission_name.to_owned()))
            .await
            .map_err(|e| {
                error!("Failed to check user permission: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let count_result: Vec<serde_json::Value> = response.take(0).map_err(|e| {
            error!("Failed to parse permission check result: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if count_result.is_empty() {
            return Ok(false);
        }

        let count = count_result[0].get("count")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        Ok(count > 0)
    }

    pub async fn check_user_role(&self, user_id: &str, role_name: &str) -> Result<bool, AuthError> {
        let user_id_bracketed = format!("user:⟨{}⟩", user_id);
        let user_id_plain = format!("user:{}", user_id);
        let user_id_quoted = format!("user:`{}`", user_id);
        
        let query = r#"
            SELECT count() as count
            FROM user_role
            WHERE type::string(user_id) IN [$user_id_bracketed, $user_id_plain, $user_id_quoted]
              AND role_id IN (SELECT VALUE id FROM role WHERE name = $role_name)
            GROUP ALL
        "#;

        let mut response = self.db.client
            .query(query)
            .bind(("user_id_bracketed", user_id_bracketed))
            .bind(("user_id_plain", user_id_plain))
            .bind(("user_id_quoted", user_id_quoted))
            .bind(("role_name", role_name.to_owned()))
            .await
            .map_err(|e| {
                error!("Failed to check user role: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let count_result: Vec<serde_json::Value> = response.take(0).map_err(|e| {
            error!("Failed to parse role check result: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if count_result.is_empty() {
            return Ok(false);
        }

        let count = count_result[0].get("count")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        Ok(count > 0)
    }

    pub async fn get_user_permissions(&self, user_id: &str) -> Result<Vec<String>, AuthError> {
        let user_id_bracketed = format!("user:⟨{}⟩", user_id);
        let user_id_plain = format!("user:{}", user_id);
        let user_id_quoted = format!("user:`{}`", user_id);
        
        let query = r#"
            SELECT name
            FROM permission
            WHERE id IN (
                SELECT VALUE permission_id FROM role_permission
                WHERE role_id IN (
                    SELECT VALUE role_id
                    FROM user_role
                    WHERE type::string(user_id) IN [$user_id_bracketed, $user_id_plain, $user_id_quoted]
                )
            )
        "#;

        let mut response = self.db.client
            .query(query)
            .bind(("user_id_bracketed", user_id_bracketed))
            .bind(("user_id_plain", user_id_plain))
            .bind(("user_id_quoted", user_id_quoted))
            .await
            .map_err(|e| {
                error!("Failed to get user permissions: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let permission_data: Vec<serde_json::Value> = response.take(0).map_err(|e| {
            error!("Failed to parse user permissions: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        let mut permissions: Vec<String> = permission_data
            .into_iter()
            .map(|data| data["name"].as_str().unwrap_or("").to_string())
            .filter(|name| !name.is_empty())
            .collect();
        permissions.sort();
        permissions.dedup();

        Ok(permissions)
    }
}
