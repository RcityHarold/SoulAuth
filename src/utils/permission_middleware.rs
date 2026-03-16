use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    Extension,
};
use std::sync::Arc;
use tracing::{error, warn, debug};

use crate::{
    error::AuthError,
    models::user::User,
    services::{database::Database, rbac::RBACService},
};

fn user_id_from_record(user: &User) -> Result<String, StatusCode> {
    let rid = user.id.as_ref().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(crate::utils::record_id::record_id_key_to_string(rid))
}

/// 权限检查中间件
/// 检查当前用户是否具有指定的权限
pub async fn check_permission<B>(
    State(db): State<Arc<Database>>,
    Extension(user): Extension<User>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    // 从请求路径和方法推断所需权限
    let required_permission = extract_required_permission(&req);
    
    if let Some(permission) = required_permission {
        let rbac_service = RBACService::new(db);
        let user_id = user_id_from_record(&user)?;

        match rbac_service.check_user_permission(&user_id, &permission).await {
            Ok(has_permission) => {
                if !has_permission {
                    warn!("User '{}' denied access to '{}' - missing permission '{}'", 
                          user.email, req.uri(), permission);
                    return Err(StatusCode::FORBIDDEN);
                }
                debug!("User '{}' granted access to '{}' with permission '{}'", 
                       user.email, req.uri(), permission);
            }
            Err(e) => {
                error!("Failed to check permission for user '{}': {}", user.email, e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    Ok(next.run(req).await)
}

/// 角色检查中间件
/// 检查当前用户是否具有指定的角色
pub async fn check_role<B>(
    State(db): State<Arc<Database>>,
    Extension(user): Extension<User>,
    required_role: String,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let rbac_service = RBACService::new(db);
    let user_id = user_id_from_record(&user)?;

    match rbac_service.check_user_role(&user_id, &required_role).await {
        Ok(has_role) => {
            if !has_role {
                warn!("User '{}' denied access to '{}' - missing role '{}'", 
                      user.email, req.uri(), required_role);
                return Err(StatusCode::FORBIDDEN);
            }
            debug!("User '{}' granted access to '{}' with role '{}'", 
                   user.email, req.uri(), required_role);
        }
        Err(e) => {
            error!("Failed to check role for user '{}': {}", user.email, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    Ok(next.run(req).await)
}

/// 管理员权限检查中间件
pub async fn check_admin_permission<B>(
    State(db): State<Arc<Database>>,
    Extension(user): Extension<User>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let rbac_service = RBACService::new(db);
    let user_id = user_id_from_record(&user)?;

    // 检查是否是管理员角色
    match rbac_service.check_user_role(&user_id, "admin").await {
        Ok(is_admin) => {
            if !is_admin {
                warn!("User '{}' denied admin access to '{}'", user.email, req.uri());
                return Err(StatusCode::FORBIDDEN);
            }
            debug!("Admin user '{}' granted access to '{}'", user.email, req.uri());
        }
        Err(e) => {
            error!("Failed to check admin role for user '{}': {}", user.email, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    Ok(next.run(req).await)
}

/// 从请求路径和方法中提取所需的权限
fn extract_required_permission<B>(req: &Request<B>) -> Option<String> {
    let path = req.uri().path();
    let method = req.method().as_str();

    // 基于路径和HTTP方法映射权限
    match (method, path) {
        // 用户管理权限
        ("GET", path) if path.starts_with("/api/users") => Some("users.read".to_string()),
        ("POST", "/api/users") => Some("users.write".to_string()),
        ("PUT", path) if path.starts_with("/api/users/") => Some("users.write".to_string()),
        ("PATCH", path) if path.starts_with("/api/users/") => Some("users.write".to_string()),
        ("DELETE", path) if path.starts_with("/api/users/") => Some("users.delete".to_string()),

        // 角色管理权限
        ("GET", path) if path.starts_with("/api/roles") => Some("roles.read".to_string()),
        ("POST", "/api/roles") => Some("roles.write".to_string()),
        ("PUT", path) if path.starts_with("/api/roles/") => Some("roles.write".to_string()),
        ("PATCH", path) if path.starts_with("/api/roles/") => Some("roles.write".to_string()),
        ("DELETE", path) if path.starts_with("/api/roles/") => Some("roles.delete".to_string()),

        // 权限管理权限
        ("GET", path) if path.starts_with("/api/permissions") => Some("permissions.read".to_string()),
        ("POST", "/api/permissions") => Some("permissions.write".to_string()),
        ("PUT", path) if path.starts_with("/api/permissions/") => Some("permissions.write".to_string()),
        ("PATCH", path) if path.starts_with("/api/permissions/") => Some("permissions.write".to_string()),
        ("DELETE", path) if path.starts_with("/api/permissions/") => Some("permissions.delete".to_string()),

        // 安全管理权限
        ("GET", path) if path.starts_with("/api/security") => Some("security.read".to_string()),
        ("POST", path) if path.starts_with("/api/security") => Some("security.write".to_string()),

        // 审计权限
        ("GET", path) if path.starts_with("/api/audit") => Some("audit.read".to_string()),

        // 用户角色分配权限
        ("POST", path) if path.contains("/roles") && path.contains("/assign") => Some("roles.write".to_string()),
        ("DELETE", path) if path.contains("/roles") && path.contains("/remove") => Some("roles.write".to_string()),

        // 角色权限分配权限
        ("POST", path) if path.contains("/permissions") && path.contains("/assign") => Some("permissions.write".to_string()),
        ("DELETE", path) if path.contains("/permissions") && path.contains("/remove") => Some("permissions.write".to_string()),

        // 默认情况下不需要特殊权限
        _ => None,
    }
}

/// 权限检查宏（返回AuthError），用于简化权限检查代码
#[macro_export]
macro_rules! require_permission {
    ($db:expr, $user_id:expr, $permission:expr) => {{
        let rbac_service = crate::services::rbac::RBACService::new($db.clone());
        
        match rbac_service.check_user_permission($user_id, $permission).await {
            Ok(has_permission) => {
                if !has_permission {
                    return Err(crate::error::AuthError::Forbidden("Insufficient permissions".to_string()));
                }
            }
            Err(e) => {
                return Err(crate::error::AuthError::DatabaseError(format!("Permission check failed: {}", e)));
            }
        }
    }};
}

/// 权限检查宏（返回StatusCode），用于返回StatusCode的路由处理器
#[macro_export]
macro_rules! require_permission_status {
    ($db:expr, $user_id:expr, $permission:expr) => {{
        let rbac_service = crate::services::rbac::RBACService::new($db.clone());
        
        match rbac_service.check_user_permission($user_id, $permission).await {
            Ok(has_permission) => {
                if !has_permission {
                    return Err(axum::http::StatusCode::FORBIDDEN);
                }
            }
            Err(_) => {
                return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }};
}

/// 角色检查宏
#[macro_export]
macro_rules! require_role {
    ($db:expr, $user_id:expr, $role:expr) => {{
        let rbac_service = crate::services::rbac::RBACService::new($db.clone());
        
        match rbac_service.check_user_role($user_id, $role).await {
            Ok(has_role) => {
                if !has_role {
                    return Err(crate::error::AuthError::Forbidden("Insufficient role".to_string()));
                }
            }
            Err(e) => {
                return Err(crate::error::AuthError::DatabaseError(format!("Role check failed: {}", e)));
            }
        }
    }};
}

/// 管理员权限检查宏
#[macro_export]
macro_rules! require_admin {
    ($db:expr, $user_id:expr) => {{
        crate::require_role!($db, $user_id, "admin");
    }};
}
