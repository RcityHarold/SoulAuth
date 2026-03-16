use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::SurrealValue;

/// 账户锁定状态
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue, PartialEq)]
pub enum LockoutStatus {
    /// 正常状态
    Normal,
    /// 已锁定
    Locked,
    /// 临时锁定（短期）
    TemporaryLocked,
}

/// 账户锁定记录
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct AccountLockout {
    /// 用户ID或IP地址
    pub identifier: String,
    /// 锁定类型（user或ip）
    pub lockout_type: LockoutType,
    /// 失败尝试次数
    pub failed_attempts: u32,
    /// 锁定状态
    pub status: LockoutStatus,
    /// 锁定开始时间
    pub locked_at: Option<DateTime<Utc>>,
    /// 锁定结束时间
    pub locked_until: Option<DateTime<Utc>>,
    /// 最后失败尝试时间
    pub last_attempt_at: DateTime<Utc>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

/// 锁定类型
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue, PartialEq)]
pub enum LockoutType {
    /// 基于用户账户的锁定
    User,
    /// 基于IP地址的锁定
    IpAddress,
}

/// 锁定配置
#[derive(Debug, Clone)]
pub struct LockoutConfig {
    /// 最大失败尝试次数
    pub max_attempts: u32,
    /// 锁定持续时间（分钟）
    pub lockout_duration_minutes: u32,
    /// 失败尝试重置时间窗口（分钟）
    pub reset_window_minutes: u32,
    /// 是否启用IP锁定
    pub enable_ip_lockout: bool,
    /// 是否启用用户锁定
    pub enable_user_lockout: bool,
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,                    // 5次失败尝试
            lockout_duration_minutes: 15,      // 锁定15分钟
            reset_window_minutes: 60,          // 1小时内重置计数
            enable_ip_lockout: true,
            enable_user_lockout: true,
        }
    }
}

impl AccountLockout {
    /// 创建新的账户锁定记录
    pub fn new(identifier: String, lockout_type: LockoutType) -> Self {
        let now = Utc::now();
        Self {
            identifier,
            lockout_type,
            failed_attempts: 0,
            status: LockoutStatus::Normal,
            locked_at: None,
            locked_until: None,
            last_attempt_at: now,
            created_at: now,
            updated_at: now,
        }
    }

    /// 记录失败尝试
    pub fn record_failed_attempt(&mut self, config: &LockoutConfig) {
        self.failed_attempts += 1;
        self.last_attempt_at = Utc::now();
        self.updated_at = Utc::now();

        // 检查是否需要锁定
        if self.failed_attempts >= config.max_attempts {
            self.lock_account(config.lockout_duration_minutes);
        }
    }

    /// 锁定账户
    pub fn lock_account(&mut self, duration_minutes: u32) {
        let now = Utc::now();
        self.status = LockoutStatus::Locked;
        self.locked_at = Some(now);
        self.locked_until = Some(now + chrono::Duration::minutes(duration_minutes as i64));
        self.updated_at = now;
    }

    /// 解锁账户
    pub fn unlock_account(&mut self) {
        self.status = LockoutStatus::Normal;
        self.failed_attempts = 0;
        self.locked_at = None;
        self.locked_until = None;
        self.updated_at = Utc::now();
    }

    /// 检查账户是否被锁定
    pub fn is_locked(&self) -> bool {
        match self.status {
            LockoutStatus::Normal => false,
            LockoutStatus::Locked | LockoutStatus::TemporaryLocked => {
                if let Some(locked_until) = self.locked_until {
                    // 检查锁定是否已过期
                    Utc::now() < locked_until
                } else {
                    true
                }
            }
        }
    }

    /// 检查锁定是否已过期
    pub fn is_lock_expired(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            Utc::now() >= locked_until
        } else {
            false
        }
    }

    /// 获取剩余锁定时间（秒）
    pub fn remaining_lockout_seconds(&self) -> Option<i64> {
        if let Some(locked_until) = self.locked_until {
            let remaining = locked_until - Utc::now();
            if remaining.num_seconds() > 0 {
                Some(remaining.num_seconds())
            } else {
                None
            }
        } else {
            None
        }
    }

    /// 检查失败尝试是否应该重置（基于时间窗口）
    pub fn should_reset_attempts(&self, config: &LockoutConfig) -> bool {
        let reset_threshold = Utc::now() - chrono::Duration::minutes(config.reset_window_minutes as i64);
        self.last_attempt_at < reset_threshold
    }
}

/// 锁定检查结果
#[derive(Debug, Clone, Serialize)]
pub struct LockoutCheckResult {
    /// 是否被锁定
    pub is_locked: bool,
    /// 剩余失败尝试次数
    pub remaining_attempts: u32,
    /// 剩余锁定时间（秒）
    pub remaining_lockout_seconds: Option<i64>,
    /// 锁定类型
    pub lockout_type: Option<LockoutType>,
    /// 提示消息
    pub message: String,
}

impl LockoutCheckResult {
    /// 创建正常状态的检查结果
    pub fn normal(remaining_attempts: u32) -> Self {
        Self {
            is_locked: false,
            remaining_attempts,
            remaining_lockout_seconds: None,
            lockout_type: None,
            message: format!("Login allowed. {} attempts remaining.", remaining_attempts),
        }
    }

    /// 创建锁定状态的检查结果
    pub fn locked(lockout_type: LockoutType, remaining_seconds: Option<i64>) -> Self {
        let message = if let Some(seconds) = remaining_seconds {
            let minutes = seconds / 60;
            if minutes > 0 {
                format!("Account locked. Try again in {} minutes.", minutes)
            } else {
                format!("Account locked. Try again in {} seconds.", seconds)
            }
        } else {
            "Account is locked.".to_string()
        };

        Self {
            is_locked: true,
            remaining_attempts: 0,
            remaining_lockout_seconds: remaining_seconds,
            lockout_type: Some(lockout_type),
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_lockout_creation() {
        let lockout = AccountLockout::new("test_user".to_string(), LockoutType::User);
        
        assert_eq!(lockout.identifier, "test_user");
        assert_eq!(lockout.lockout_type, LockoutType::User);
        assert_eq!(lockout.failed_attempts, 0);
        assert_eq!(lockout.status, LockoutStatus::Normal);
        assert!(!lockout.is_locked());
    }

    #[test]
    fn test_failed_attempt_recording() {
        let mut lockout = AccountLockout::new("test_user".to_string(), LockoutType::User);
        let config = LockoutConfig::default();
        
        // 记录几次失败尝试
        for i in 1..config.max_attempts {
            lockout.record_failed_attempt(&config);
            assert_eq!(lockout.failed_attempts, i);
            assert!(!lockout.is_locked());
        }
        
        // 第5次失败尝试应该触发锁定
        lockout.record_failed_attempt(&config);
        assert_eq!(lockout.failed_attempts, config.max_attempts);
        assert!(lockout.is_locked());
    }

    #[test]
    fn test_unlock_account() {
        let mut lockout = AccountLockout::new("test_user".to_string(), LockoutType::User);
        let config = LockoutConfig::default();
        
        // 触发锁定
        for _ in 0..config.max_attempts {
            lockout.record_failed_attempt(&config);
        }
        assert!(lockout.is_locked());
        
        // 解锁
        lockout.unlock_account();
        assert!(!lockout.is_locked());
        assert_eq!(lockout.failed_attempts, 0);
    }

    #[test]
    fn test_lock_expiration() {
        let mut lockout = AccountLockout::new("test_user".to_string(), LockoutType::User);
        
        // 手动设置一个已过期的锁定
        lockout.status = LockoutStatus::Locked;
        lockout.locked_until = Some(Utc::now() - chrono::Duration::minutes(1));
        
        assert!(lockout.is_lock_expired());
        assert!(!lockout.is_locked()); // 应该返回false因为锁定已过期
    }

    #[test]
    fn test_lockout_check_result() {
        let normal_result = LockoutCheckResult::normal(3);
        assert!(!normal_result.is_locked);
        assert_eq!(normal_result.remaining_attempts, 3);
        
        let locked_result = LockoutCheckResult::locked(LockoutType::User, Some(300));
        assert!(locked_result.is_locked);
        assert_eq!(locked_result.remaining_attempts, 0);
        assert_eq!(locked_result.remaining_lockout_seconds, Some(300));
    }
}
