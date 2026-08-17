//! RBAC 权限断言宏。
//!
//! 这里原本还有三个 axum 中间件（`check_permission` / `check_role` /
//! `check_admin_permission`），它们依赖一个从未被塞进 extension 的 `User`，
//! 并且从未被 `.layer()` 挂载过 —— 属于纯死代码，已删除。
//! 现在鉴权统一走 `utils::jwt::AuthedUser` 提取器 + 下面的断言宏。

/// 记录一次权限拒绝。
///
/// 审计子系统一直在查 `permission_denied`，但此前没有任何地方写过它。
/// 这里放在宏里统一埋点，所有走 `require_permission!` 的接口自动覆盖。
#[doc(hidden)]
pub fn record_permission_denied(
    db: &std::sync::Arc<crate::services::database::Database>,
    user_id: &str,
    permission: &str,
) {
    use crate::{
        models::user_activity::{ActivityCategory, ActivityStatus},
        services::audit_logger::{actions, AuditEvent, AuditLogger},
    };

    AuditLogger::new(db.clone()).record(
        AuditEvent::new(
            actions::PERMISSION_DENIED,
            ActivityCategory::Permissions,
            ActivityStatus::Failed,
            // 这层拿不到请求上下文，IP / UA 留空而不是编造。
            String::new(),
            String::new(),
        )
        .with_user(user_id.to_string())
        .with_details(serde_json::json!({ "permission": permission })),
    );
}

/// 权限检查宏（返回 `AuthError`）。
#[macro_export]
macro_rules! require_permission {
    ($db:expr, $user_id:expr, $permission:expr) => {{
        let rbac_service = $crate::services::rbac::RBACService::new($db.clone());

        match rbac_service.check_user_permission($user_id, $permission).await {
            Ok(has_permission) => {
                if !has_permission {
                    $crate::utils::permission_middleware::record_permission_denied(
                        &$db.clone(),
                        $user_id,
                        $permission,
                    );
                    return Err($crate::error::AuthError::Forbidden(format!(
                        "Missing permission: {}",
                        $permission
                    )));
                }
            }
            Err(e) => {
                return Err($crate::error::AuthError::DatabaseError(format!(
                    "Permission check failed: {}",
                    e
                )));
            }
        }
    }};
}

/// 权限检查宏（返回 `StatusCode`），用于返回 `StatusCode` 的路由处理器。
#[macro_export]
macro_rules! require_permission_status {
    ($db:expr, $user_id:expr, $permission:expr) => {{
        let rbac_service = $crate::services::rbac::RBACService::new($db.clone());

        match rbac_service.check_user_permission($user_id, $permission).await {
            Ok(has_permission) => {
                if !has_permission {
                    $crate::utils::permission_middleware::record_permission_denied(
                        &$db.clone(),
                        $user_id,
                        $permission,
                    );
                    return Err(axum::http::StatusCode::FORBIDDEN);
                }
            }
            Err(_) => {
                return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }};
}

/// 角色检查宏。
#[macro_export]
macro_rules! require_role {
    ($db:expr, $user_id:expr, $role:expr) => {{
        let rbac_service = $crate::services::rbac::RBACService::new($db.clone());

        match rbac_service.check_user_role($user_id, $role).await {
            Ok(has_role) => {
                if !has_role {
                    return Err($crate::error::AuthError::Forbidden(format!(
                        "Missing role: {}",
                        $role
                    )));
                }
            }
            Err(e) => {
                return Err($crate::error::AuthError::DatabaseError(format!(
                    "Role check failed: {}",
                    e
                )));
            }
        }
    }};
}

/// 管理员角色检查宏。
#[macro_export]
macro_rules! require_admin {
    ($db:expr, $user_id:expr) => {{
        $crate::require_role!($db, $user_id, "admin");
    }};
}
