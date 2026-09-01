//! 认证事件埋点。
//!
//! 审计子系统一直在查这些 action：`login_success` / `login_failed` /
//! `oauth_login` / `password_reset` / `permission_denied` / `rate_limit_violation`，
//! 但**全代码库没有任何地方写过它们** —— `log_user_activity` 只有 5 个调用点，
//! 全在用户档案/偏好/账号状态那几个接口上。结果就是审计报表永远是空的。
//!
//! 这个模块负责在认证链路上补齐埋点。三条硬性约束：
//!
//! * **绝不影响主流程**：`record` 不落库，只把事件投进队列就返回；
//! * **绝不丢事件**：队列由一个专用写入任务消费，写失败会重试，
//!   进程关闭时先把队列排空再退出（见 `flush`）；
//! * **绝不记录凭据**：只记 action / 分类 / 状态 / IP / UA 和少量非敏感上下文。
//!
//! 这里以前是 `tokio::spawn` 一个一次性任务直接写库：写失败只打一行日志，
//! 而进程一退出，还没跑起来的那些任务连日志都不会留。

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, warn};

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
    /// 管理员手工解除锁定。与 ACCOUNT_LOCKED 成对 —— 只记上锁不记解锁的话，
    /// 审计里会留下一串永远没有下文的锁定事件。
    pub const LOCKOUT_CLEARED: &str = "lockout_cleared";
}

/// 队列容量。
///
/// 满了不是丢事件，而是让 `record` 退化成「起一个任务等队列」——
/// 也就是改动前的行为。给得宽一点，正常负载下走不到那条分支。
const QUEUE_CAPACITY: usize = 4096;

/// 单条事件的写入重试次数。数据库抖一下不该让事件消失。
const WRITE_ATTEMPTS: u32 = 3;

/// 关闭时等待队列排空的上限。超时宁可退出，也不能把进程挂在这里。
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

enum Msg {
    Event(Box<AuditEvent>),
    /// 排空信号：写入任务处理到它时，说明它前面的事件都已落库。
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct AuditLogger {
    tx: mpsc::Sender<Msg>,
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
    /// 建队列并起写入任务。写入任务与进程同生命周期。
    pub fn new(db: Arc<Database>) -> Self {
        let (tx, mut rx) = mpsc::channel::<Msg>(QUEUE_CAPACITY);

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    Msg::Event(event) => write_with_retry(&db, *event).await,
                    // 排空信号按序到达：能收到它，就说明它前面排队的事件
                    // 都已经写完了。回执发不出去只意味着等待方先走了。
                    Msg::Flush(ack) => {
                        let _ = ack.send(());
                    }
                }
            }
        });

        Self { tx }
    }

    /// 记录一条事件。不落库，只投队列，因此不阻塞调用方。
    pub fn record(&self, event: AuditEvent) {
        let msg = Msg::Event(Box::new(event));
        match self.tx.try_send(msg) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(msg)) => {
                // 队列满说明写入任务被数据库拖住了。这时**不丢**事件：
                // 起一个任务去等位置，代价是这一条的顺序可能落到后面。
                warn!("Audit queue is full; the writer is falling behind");
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    if tx.send(msg).await.is_err() {
                        error!("Audit event dropped: the writer has stopped");
                    }
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("Audit event dropped: the writer has stopped");
            }
        }
    }

    /// 等队列里已排队的事件全部落库。
    ///
    /// 关闭流程在停止接受新请求之后调用它 —— 这一步是「进程退出不丢事件」
    /// 的全部依据。超时就放弃等待：卡住不退出比丢几条事件更糟。
    pub async fn flush(&self) {
        let (ack, wait) = oneshot::channel();
        if self.tx.send(Msg::Flush(ack)).await.is_err() {
            return;
        }
        if tokio::time::timeout(FLUSH_TIMEOUT, wait).await.is_err() {
            warn!("Audit queue did not drain within {FLUSH_TIMEOUT:?}");
        }
    }
}

/// 写一条事件，失败重试。
///
/// 重试的是数据库抖动这类瞬时故障。用尽仍失败才记日志 —— 那一行是最后的线索，
/// 所以要带上 action，不能只有一句 "Failed to write audit event"。
async fn write_with_retry(db: &Database, event: AuditEvent) {
    let action = event.action;
    let mut last_err = None;

    for attempt in 1..=WRITE_ATTEMPTS {
        match write_event(db, &event).await {
            Ok(()) => return,
            Err(e) => {
                last_err = Some(e);
                if attempt < WRITE_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(50 * u64::from(attempt))).await;
                }
            }
        }
    }

    error!(
        action,
        "Failed to write audit event after {WRITE_ATTEMPTS} attempts: {}",
        last_err.map(|e| e.to_string()).unwrap_or_default()
    );
}

async fn write_event(db: &Database, event: &AuditEvent) -> crate::error::Result<()> {
    // user_id 是 `option<record<actor_identity>>`：没有对应主体时写 NONE。
    //
    // 审计归因到**身份根**而不是 user 行 —— 这也是 GA-06 要求的方向：
    // 归因主体要跨 user 行的生命周期保持稳定。传进来的仍是 user id，
    // 所以这里用子查询把它解析成 actor ref，与会话查询同一种写法。
    let sql = if event.user_id.is_some() {
        r#"
            CREATE user_activity CONTENT {
                user_id: (SELECT VALUE subject_id FROM type::record('user', $user_key))[0],
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
