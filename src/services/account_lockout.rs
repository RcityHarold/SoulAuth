use crate::{
    config::Config,
    error::{AuthError, Result},
    models::{
        account_lockout::{
            AccountLockout, LockoutCheckResult, LockoutConfig, LockoutStatus, LockoutType,
        },
        user_activity::{ActivityCategory, ActivityStatus},
    },
    services::{
        audit_logger::{actions, AuditEvent, AuditLogger},
        database::Database,
    },
};
use chrono::Utc;
use std::sync::Arc;
use tracing::{info, warn, debug};

/// 账户锁定服务
pub struct AccountLockoutService {
    db: Arc<Database>,
    config: LockoutConfig,
    audit: Arc<AuditLogger>,
}

impl AccountLockoutService {
    /// 创建新的账户锁定服务实例
    pub fn new(db: Arc<Database>, _config: Config, audit: Arc<AuditLogger>) -> Result<Self> {
        Ok(Self {
            db,
            config: LockoutConfig::default(),
            audit,
        })
    }

    /// 使用自定义配置创建服务
    pub fn with_config(
        db: Arc<Database>,
        config: LockoutConfig,
        audit: Arc<AuditLogger>,
    ) -> Result<Self> {
        Ok(Self { db, config, audit })
    }

    /// 账号 / IP 被锁定是安全事件，必须进审计。
    fn record_lockout_event(&self, identifier: &str, lockout_type: &LockoutType, attempts: u32) {
        let is_ip = matches!(lockout_type, LockoutType::IpAddress);
        let event = AuditEvent::new(
            actions::ACCOUNT_LOCKED,
            ActivityCategory::Security,
            ActivityStatus::Warning,
            if is_ip { identifier.to_string() } else { String::new() },
            String::new(),
        )
        .with_details(serde_json::json!({
            "scope": if is_ip { "ip" } else { "account" },
            "failed_attempts": attempts,
        }));

        // 账号维度的 identifier 是邮箱，不是用户 ID，所以不往 user_id 上挂。
        self.audit.record(event);
    }

    pub fn max_attempts(&self) -> u32 {
        self.config.max_attempts
    }

    /// 检查账户是否被锁定（用户维度）
    pub async fn check_user_lockout(&self, user_id: &str) -> Result<LockoutCheckResult> {
        if !self.config.enable_user_lockout {
            return Ok(LockoutCheckResult::normal(self.config.max_attempts));
        }

        match self.get_lockout_record(user_id, LockoutType::User).await {
            Ok(mut lockout) => {
                // 检查锁定是否已过期
                if lockout.is_lock_expired() && lockout.status != LockoutStatus::Normal {
                    lockout.unlock_account();
                    self.save_lockout_record(&lockout).await?;
                    return Ok(LockoutCheckResult::normal(self.config.max_attempts));
                }

                // 检查是否应该重置失败尝试计数
                if lockout.should_reset_attempts(&self.config) && lockout.status == LockoutStatus::Normal {
                    lockout.failed_attempts = 0;
                    lockout.updated_at = Utc::now();
                    self.save_lockout_record(&lockout).await?;
                }

                if lockout.is_locked() {
                    Ok(LockoutCheckResult::locked(
                        LockoutType::User,
                        lockout.remaining_lockout_seconds(),
                    ))
                } else {
                    let remaining = self.config.max_attempts.saturating_sub(lockout.failed_attempts);
                    Ok(LockoutCheckResult::normal(remaining))
                }
            }
            Err(AuthError::UserNotFound) => {
                // 没有锁定记录，返回正常状态
                Ok(LockoutCheckResult::normal(self.config.max_attempts))
            }
            Err(e) => Err(e),
        }
    }

    /// 检查IP地址是否被锁定
    pub async fn check_ip_lockout(&self, ip_address: &str) -> Result<LockoutCheckResult> {
        if !self.config.enable_ip_lockout {
            return Ok(LockoutCheckResult::normal(self.config.max_attempts));
        }

        match self.get_lockout_record(ip_address, LockoutType::IpAddress).await {
            Ok(mut lockout) => {
                // 检查锁定是否已过期
                if lockout.is_lock_expired() && lockout.status != LockoutStatus::Normal {
                    lockout.unlock_account();
                    self.save_lockout_record(&lockout).await?;
                    return Ok(LockoutCheckResult::normal(self.config.max_attempts));
                }

                // 检查是否应该重置失败尝试计数
                if lockout.should_reset_attempts(&self.config) && lockout.status == LockoutStatus::Normal {
                    lockout.failed_attempts = 0;
                    lockout.updated_at = Utc::now();
                    self.save_lockout_record(&lockout).await?;
                }

                if lockout.is_locked() {
                    Ok(LockoutCheckResult::locked(
                        LockoutType::IpAddress,
                        lockout.remaining_lockout_seconds(),
                    ))
                } else {
                    let remaining = self.config.max_attempts.saturating_sub(lockout.failed_attempts);
                    Ok(LockoutCheckResult::normal(remaining))
                }
            }
            Err(AuthError::UserNotFound) => {
                // 没有锁定记录，返回正常状态
                Ok(LockoutCheckResult::normal(self.config.max_attempts))
            }
            Err(e) => Err(e),
        }
    }

    /// 记录失败的登录尝试（用户维度）
    pub async fn record_failed_user_attempt(&self, user_id: &str) -> Result<()> {
        if !self.config.enable_user_lockout {
            return Ok(());
        }

        info!("Recording failed login attempt for user: {}", user_id);

        let mut lockout = match self.get_lockout_record(user_id, LockoutType::User).await {
            Ok(lockout) => lockout,
            Err(AuthError::UserNotFound) => {
                // 创建新的锁定记录
                AccountLockout::new(user_id.to_string(), LockoutType::User)
            }
            Err(e) => return Err(e),
        };

        lockout.record_failed_attempt(&self.config);
        
        if lockout.is_locked() {
            warn!("User account locked: {} (attempts: {})", user_id, lockout.failed_attempts);
            self.record_lockout_event(user_id, &LockoutType::User, lockout.failed_attempts);
        } else {
            debug!("Failed attempt recorded for user: {} (attempts: {}/{})", 
                   user_id, lockout.failed_attempts, self.config.max_attempts);
        }

        self.save_lockout_record(&lockout).await?;
        Ok(())
    }

    /// 记录失败的登录尝试（IP维度）
    pub async fn record_failed_ip_attempt(&self, ip_address: &str) -> Result<()> {
        if !self.config.enable_ip_lockout {
            return Ok(());
        }

        info!("Recording failed login attempt for IP: {}", ip_address);

        let mut lockout = match self.get_lockout_record(ip_address, LockoutType::IpAddress).await {
            Ok(lockout) => lockout,
            Err(AuthError::UserNotFound) => {
                // 创建新的锁定记录
                AccountLockout::new(ip_address.to_string(), LockoutType::IpAddress)
            }
            Err(e) => return Err(e),
        };

        lockout.record_failed_attempt(&self.config);
        
        if lockout.is_locked() {
            warn!("IP address locked: {} (attempts: {})", ip_address, lockout.failed_attempts);
            self.record_lockout_event(ip_address, &LockoutType::IpAddress, lockout.failed_attempts);
        } else {
            debug!("Failed attempt recorded for IP: {} (attempts: {}/{})", 
                   ip_address, lockout.failed_attempts, self.config.max_attempts);
        }

        self.save_lockout_record(&lockout).await?;
        Ok(())
    }

    /// 重置用户的失败尝试计数
    pub async fn reset_user_attempts(&self, user_id: &str) -> Result<()> {
        info!("Resetting failed attempts for user: {}", user_id);

        match self.get_lockout_record(user_id, LockoutType::User).await {
            Ok(mut lockout) => {
                lockout.unlock_account();
                self.save_lockout_record(&lockout).await?;
            }
            Err(AuthError::UserNotFound) => {
                // 没有记录，无需重置
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// 重置IP的失败尝试计数
    pub async fn reset_ip_attempts(&self, ip_address: &str) -> Result<()> {
        info!("Resetting failed attempts for IP: {}", ip_address);

        match self.get_lockout_record(ip_address, LockoutType::IpAddress).await {
            Ok(mut lockout) => {
                lockout.unlock_account();
                self.save_lockout_record(&lockout).await?;
            }
            Err(AuthError::UserNotFound) => {
                // 没有记录，无需重置
            }
            Err(e) => return Err(e),
        }

        Ok(())
    }

    /// 手动解锁用户账户
    pub async fn unlock_user(&self, user_id: &str) -> Result<bool> {
        info!("Manually unlocking user: {}", user_id);

        match self.get_lockout_record(user_id, LockoutType::User).await {
            Ok(mut lockout) => {
                if lockout.is_locked() {
                    lockout.unlock_account();
                    self.save_lockout_record(&lockout).await?;
                    info!("User unlocked successfully: {}", user_id);
                    Ok(true)
                } else {
                    Ok(false) // 用户本来就没有被锁定
                }
            }
            Err(AuthError::UserNotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 手动解锁IP地址
    pub async fn unlock_ip(&self, ip_address: &str) -> Result<bool> {
        info!("Manually unlocking IP: {}", ip_address);

        match self.get_lockout_record(ip_address, LockoutType::IpAddress).await {
            Ok(mut lockout) => {
                if lockout.is_locked() {
                    lockout.unlock_account();
                    self.save_lockout_record(&lockout).await?;
                    info!("IP unlocked successfully: {}", ip_address);
                    Ok(true)
                } else {
                    Ok(false) // IP本来就没有被锁定
                }
            }
            Err(AuthError::UserNotFound) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 获取锁定配置
    pub fn get_config(&self) -> &LockoutConfig {
        &self.config
    }

    /// 清理过期的锁定记录
    pub async fn cleanup_expired_lockouts(&self) -> Result<u32> {
        let query = r#"
            DELETE account_lockout 
            WHERE locked_until < type::datetime($now) 
            AND status IN ['Locked', 'TemporaryLocked']
        "#;

        // `Utc::now().to_string()` 产出 "2026-08-05 08:43:36.837 UTC"，
        // 不是 RFC3339，`type::datetime()` 转不了 —— 定时清理任务因此每小时报错一次。
        let now = Utc::now().to_rfc3339();
        let _result = self
            .db
            .raw_query(
                "cleanup_expired_lockouts",
                query,
                serde_json::json!({ "now": now }),
            )
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        info!("Cleaned up expired lockout records");
        Ok(0) // SurrealDB DELETE 不返回删除计数，这里返回0
    }

    /// 从数据库获取锁定记录
    async fn get_lockout_record(&self, identifier: &str, lockout_type: LockoutType) -> Result<AccountLockout> {
        // 时间列必须投影成字符串：SDK 无法把原生 `Value::Datetime` 转成
        // `serde_json::Value`（报 "Expected any, got datetime"）。
        let query = r#"
            SELECT
                identifier,
                lockout_type,
                failed_attempts,
                status,
                type::string(created_at) AS created_at,
                type::string(updated_at) AS updated_at,
                type::string(last_attempt_at) AS last_attempt_at,
                IF locked_at = NONE { NONE } ELSE { type::string(locked_at) } AS locked_at,
                IF locked_until = NONE { NONE } ELSE { type::string(locked_until) } AS locked_until
            FROM account_lockout
            WHERE identifier = $identifier AND lockout_type = $lockout_type
            LIMIT 1
        "#;

        // 写路径用 serde（枚举存成 "User" / "IpAddress" 字符串），
        // 读路径若用 SurrealValue 解码则对不上（"no variants matched"）。
        // 两边必须一致，所以这里也走 serde。
        let mut result = self
            .db
            .raw_query(
                "get_lockout_record",
                query,
                serde_json::json!({
                    "identifier": identifier,
                    "lockout_type": lockout_type,
                }),
            )
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let rows: Vec<serde_json::Value> = result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        rows.into_iter()
            .next()
            .map(serde_json::from_value::<AccountLockout>)
            .transpose()
            .map_err(|e| {
                AuthError::DatabaseError(format!("Failed to parse lockout record: {e}"))
            })?
            .ok_or(AuthError::UserNotFound)
    }

    /// 保存锁定记录到数据库
    async fn save_lockout_record(&self, lockout: &AccountLockout) -> Result<()> {
        // 时间列是 `datetime`，而 raw_query 的 JSON 绑定给出的是 RFC3339 字符串，
        // 必须显式转换 —— 否则整条写入被拒，账号锁定计数永远停在 0，
        // 暴力破解防护实际上从未生效过。
        // SurrealQL doesn't support `REPLACE` in this position.
        // Use a deterministic record id so we can UPDATE (create-or-replace semantics).
        // Example: account_lockout:user:foo@example.com
        // 注意必须用 `type::record(table, id)` 两参形式。
        // 单参形式 `type::record("account_lockout:user:a@b.com")` 会在第一个冒号处
        // 截断，得到 `account_lockout:user` —— 于是所有账号共用一条记录、
        // 所有 IP 共用另一条，锁定计数根本不按对象累加。
        let lockout_type = format!("{:?}", lockout.lockout_type).to_lowercase();
        let identifier = lockout.identifier.replace(' ', "_");
        let record_id = format!("{}:{}", lockout_type, identifier);

        let query = r#"
            UPSERT type::record('account_lockout', $record_id) CONTENT {
                identifier: $identifier,
                lockout_type: $lockout_type,
                failed_attempts: $failed_attempts,
                status: $status,
                locked_at: IF $locked_at = NONE OR $locked_at = NULL {
                    NONE
                } ELSE {
                    type::datetime($locked_at)
                },
                locked_until: IF $locked_until = NONE OR $locked_until = NULL {
                    NONE
                } ELSE {
                    type::datetime($locked_until)
                },
                last_attempt_at: IF $last_attempt_at = NONE OR $last_attempt_at = NULL {
                    NONE
                } ELSE {
                    type::datetime($last_attempt_at)
                },
                created_at: type::datetime($created_at),
                updated_at: type::datetime($updated_at)
            }
        "#;

        let identifier_value = lockout.identifier.clone();
        let lockout_type_value = lockout.lockout_type.clone();
        let status_value = lockout.status.clone();
        let failed_attempts_value = lockout.failed_attempts;
        let locked_at_value = lockout.locked_at;
        let locked_until_value = lockout.locked_until;
        let last_attempt_at_value = lockout.last_attempt_at;
        let created_at_value = lockout.created_at;
        let updated_at_value = lockout.updated_at;

        let save = self
            .db
            .raw_query(
                "save_lockout_record",
                query,
                serde_json::json!({
                    "record_id": record_id,
                    "identifier": identifier_value,
                    "lockout_type": lockout_type_value,
                    "failed_attempts": failed_attempts_value,
                    "status": status_value,
                    "locked_at": locked_at_value,
                    "locked_until": locked_until_value,
                    "last_attempt_at": last_attempt_at_value,
                    "created_at": created_at_value,
                    "updated_at": updated_at_value,
                }),
            )
            .await;

        if let Err(err) = save {
            return Err(AuthError::DatabaseError(err.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lockout_config_default() {
        let config = LockoutConfig::default();
        
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.lockout_duration_minutes, 15);
        assert_eq!(config.reset_window_minutes, 60);
        assert!(config.enable_ip_lockout);
        assert!(config.enable_user_lockout);
    }

    #[test]
    fn test_lockout_check_result_creation() {
        let normal = LockoutCheckResult::normal(3);
        assert!(!normal.is_locked);
        assert_eq!(normal.remaining_attempts, 3);
        
        let locked = LockoutCheckResult::locked(LockoutType::User, Some(300));
        assert!(locked.is_locked);
        assert_eq!(locked.remaining_lockout_seconds, Some(300));
    }
}
