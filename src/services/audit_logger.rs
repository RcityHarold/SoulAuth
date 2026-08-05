//! 认证事件埋点。
//!
//! 审计子系统一直在查这些 action：`login_success` / `login_failed` /
//! `oauth_login` / `password_reset` / `permission_denied` / `rate_limit_violation`，
//! 但**全代码库没有任何地方写过它们** —— `log_user_activity` 只有 5 个调用点，
//! 全在用户档案/偏好/账号状态那几个接口上。结果就是审计报表永远是空的。
//!
//! 这个模块负责在认证链路上补齐埋点。两条硬性约束：
//!
//! * **绝不影响主流程**：写入是 fire-and-forget，失败只打日志；
//! * **绝不记录凭据**：只记 action / 分类 / 状态 / IP / UA 和少量非敏感上下文。

use std::sync::Arc;

use chrono::Utc;
use serde_json::json;
use tracing::error;

use crate::{
    models::user_activity::{ActivityCategory, ActivityStatus},
    services::database::Database,
};

/// 审计事件的 action 常量。审计查询按这些字符串聚合，改名要两边一起改。
pub mod actions {
    pub const LOGIN_SUCCESS: &str = "login_success";
    pub const LOGIN_FAILED: &str = "login_failed";
    pub const OAUTH_LOGIN: &str = "oauth_login";
    pub const LOGOUT: &str = "logout";
    pub const PASSWORD_RESET: &str = "password_reset";
    pub const MFA_FAILED: &str = "mfa_failed";
    pub const PERMISSION_DENIED: &str = "permission_denied";
    pub const RATE_LIMIT_VIOLATION: &str = "rate_limit_violation";
    pub const ACCOUNT_LOCKED: &str = "account_locked";
}

#[derive(Clone)]
pub struct AuditLogger {
    db: Arc<Database>,
}

/// 一条待写入的审计事件。
pub struct AuditEvent {
    pub action: &'static str,
    pub category: ActivityCategory,
    pub status: ActivityStatus,
    /// 用户 ID（不含表名前缀）。登录失败等场景可能为空。
    pub user_id: Option<String>,
    pub ip_address: String,
    pub user_agent: String,
    pub details: serde_json::Value,
}

impl AuditEvent {
    pub fn new(
        action: &'static str,
        category: ActivityCategory,
        status: ActivityStatus,
        ip_address: impl Into<String>,
        user_agent: impl Into<String>,
    ) -> Self {
        Self {
            action,
            category,
            status,
            user_id: None,
            ip_address: ip_address.into(),
            user_agent: user_agent.into(),
            details: json!({}),
        }
    }

    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

impl AuditLogger {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// 异步写入，不阻塞也不影响调用方。
    pub fn record(&self, event: AuditEvent) {
        let db = self.db.clone();
        tokio::spawn(async move {
            if let Err(e) = write_event(&db, event).await {
                error!("Failed to write audit event: {e}");
            }
        });
    }

}

async fn write_event(db: &Database, event: AuditEvent) -> crate::error::Result<()> {
    // user_id 是 `option<record<user>>`：没有对应用户时写 NONE。
    let sql = if event.user_id.is_some() {
        r#"
            CREATE user_activity CONTENT {
                user_id: type::record('user', $user_key),
                action: $action,
                category: $category,
                ip_address: $ip_address,
                user_agent: $user_agent,
                details: $details,
                status: $status,
                timestamp: $timestamp
            }
        "#
    } else {
        r#"
            CREATE user_activity CONTENT {
                user_id: NONE,
                action: $action,
                category: $category,
                ip_address: $ip_address,
                user_agent: $user_agent,
                details: $details,
                status: $status,
                timestamp: $timestamp
            }
        "#
    };

    db.raw_query(
        "audit_write_event",
        sql,
        json!({
            "user_key": event
                .user_id
                .as_deref()
                .map(crate::utils::record_id::normalize_user_id)
                .unwrap_or_default(),
            "action": event.action,
            "category": event.category,
            "status": event.status,
            "ip_address": event.ip_address,
            "user_agent": event.user_agent,
            "details": event.details,
            "timestamp": Utc::now().timestamp(),
        }),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_builder_sets_optional_fields() {
        let event = AuditEvent::new(
            actions::LOGIN_FAILED,
            ActivityCategory::Authentication,
            ActivityStatus::Failed,
            "203.0.113.7",
            "curl/8.0",
        );

        assert_eq!(event.action, "login_failed");
        assert!(event.user_id.is_none());
        assert_eq!(event.details, json!({}));

        let event = event
            .with_user("user-1")
            .with_details(json!({ "reason": "invalid_password" }));

        assert_eq!(event.user_id.as_deref(), Some("user-1"));
        assert_eq!(event.details["reason"], json!("invalid_password"));
    }

    #[test]
    fn action_names_match_what_the_audit_queries_look_for() {
        // 审计服务里硬编码了这些字符串，改名必须同步。
        assert_eq!(actions::LOGIN_SUCCESS, "login_success");
        assert_eq!(actions::LOGIN_FAILED, "login_failed");
        assert_eq!(actions::OAUTH_LOGIN, "oauth_login");
        assert_eq!(actions::PASSWORD_RESET, "password_reset");
        assert_eq!(actions::PERMISSION_DENIED, "permission_denied");
        assert_eq!(actions::RATE_LIMIT_VIOLATION, "rate_limit_violation");
    }
}
