use crate::{
    config::Config,
    error::{AuthError, Result},
    models::account_lockout::{
        AccountLockout, LockoutConfig, LockoutStatus, LockoutType, LockoutCheckResult
    },
    services::database::Database,
};
use chrono::Utc;
use std::sync::Arc;
use tracing::{info, warn, debug};

/// 账户锁定服务
pub struct AccountLockoutService {
    db: Database,
    config: LockoutConfig,
}

impl AccountLockoutService {
    /// 创建新的账户锁定服务实例
    pub fn new(db: Arc<Database>, _config: Config) -> Result<Self> {
        Ok(Self {
            db: (*db).clone(),
            config: LockoutConfig::default(),
        })
    }

    /// 使用自定义配置创建服务
    pub fn with_config(db: Arc<Database>, config: LockoutConfig) -> Result<Self> {
        Ok(Self {
            db: (*db).clone(),
            config,
        })
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

        let result = self.db.query(query)
            .bind(("now", Utc::now()))
            .await?;

        info!("Cleaned up expired lockout records");
        Ok(0) // SurrealDB DELETE 不返回删除计数，这里返回0
    }

    /// 从数据库获取锁定记录
    async fn get_lockout_record(&self, identifier: &str, lockout_type: LockoutType) -> Result<AccountLockout> {
        let query = "SELECT * FROM account_lockout WHERE identifier = $identifier AND lockout_type = $lockout_type";
        
        let mut result = self.db.query(query)
            .bind(("identifier", identifier.to_string()))
            .bind(("lockout_type", lockout_type))
            .await?;
        
        let lockout: Option<AccountLockout> = result.take(0)?;
        
        lockout.ok_or(AuthError::UserNotFound)
    }

    /// 保存锁定记录到数据库
    async fn save_lockout_record(&self, lockout: &AccountLockout) -> Result<()> {
        let query = r#"
            CREATE account_lockout CONTENT {
                identifier: $identifier,
                lockout_type: $lockout_type,
                failed_attempts: $failed_attempts,
                status: $status,
                locked_at: $locked_at,
                locked_until: $locked_until,
                last_attempt_at: $last_attempt_at,
                created_at: $created_at,
                updated_at: $updated_at
            } REPLACE
        "#;

        self.db.query(query)
            .bind(("identifier", lockout.identifier.clone()))
            .bind(("lockout_type", lockout.lockout_type.clone()))
            .bind(("failed_attempts", lockout.failed_attempts))
            .bind(("status", lockout.status.clone()))
            .bind(("locked_at", lockout.locked_at))
            .bind(("locked_until", lockout.locked_until))
            .bind(("last_attempt_at", lockout.last_attempt_at))
            .bind(("created_at", lockout.created_at))
            .bind(("updated_at", lockout.updated_at))
            .await?;

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
