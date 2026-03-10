use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;
use surrealdb::types::SurrealValue;

/// MFA设置状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, SurrealValue)]
pub enum MfaStatus {
    /// 未启用MFA
    Disabled,
    /// MFA设置中（生成密钥但未验证）
    Pending,
    /// MFA已启用
    Enabled,
}

/// MFA方法类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, SurrealValue)]
pub enum MfaMethod {
    /// TOTP (Time-based One-Time Password)
    Totp,
    /// SMS验证码
    Sms,
    /// 邮箱验证码
    Email,
}

/// 用户MFA配置
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct UserMfa {
    /// 用户ID
    pub user_id: String,
    /// MFA状态
    pub status: MfaStatus,
    /// MFA方法
    pub method: MfaMethod,
    /// TOTP密钥（加密存储）
    pub totp_secret: Option<String>,
    /// 备用恢复代码
    pub backup_codes: Vec<String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
    /// 最后使用时间
    pub last_used_at: Option<DateTime<Utc>>,
}

impl UserMfa {
    /// 创建新的MFA配置
    pub fn new(user_id: String, method: MfaMethod) -> Self {
        let now = Utc::now();
        Self {
            user_id,
            status: MfaStatus::Disabled,
            method,
            totp_secret: None,
            backup_codes: Vec::new(),
            created_at: now,
            updated_at: now,
            last_used_at: None,
        }
    }

    /// 生成备用恢复代码
    pub fn generate_backup_codes() -> Vec<String> {
        use rand::{distributions::Uniform, Rng};

        // 仅使用大写字母，避免数字在 is_uppercase 判断中失败
        let alphabet = Uniform::new_inclusive(b'A', b'Z');
        let mut rng = rand::thread_rng();

        (0..8)
            .map(|_| {
                (0..8)
                    .map(|_| rng.sample(alphabet) as char)
                    .collect::<String>()
            })
            .collect()
    }
}

/// 启用TOTP的请求
#[derive(Debug, Deserialize, Validate)]
pub struct EnableTotpRequest {
    /// TOTP验证码
    #[validate(length(equal = 6))]
    pub totp_code: String,
}

/// 验证TOTP的请求
#[derive(Debug, Deserialize, Validate)]
pub struct VerifyTotpRequest {
    /// TOTP验证码
    #[validate(length(equal = 6))]
    pub totp_code: String,
}

/// 使用备用代码的请求
#[derive(Debug, Deserialize, Validate)]
pub struct UseBackupCodeRequest {
    /// 备用恢复代码
    #[validate(length(equal = 8))]
    pub backup_code: String,
}

/// TOTP设置响应
#[derive(Debug, Serialize)]
pub struct TotpSetupResponse {
    /// 密钥（用于手动输入）
    pub secret: String,
    /// QR码数据URL
    pub qr_code: String,
    /// 备用恢复代码
    pub backup_codes: Vec<String>,
}

/// MFA验证响应
#[derive(Debug, Serialize)]
pub struct MfaVerificationResponse {
    /// 是否验证成功
    pub verified: bool,
    /// 认证令牌（如果验证成功）
    pub token: Option<String>,
    /// 错误消息（如果验证失败）
    pub message: Option<String>,
}

/// MFA状态响应
#[derive(Debug, Serialize)]
pub struct MfaStatusResponse {
    /// MFA是否启用
    pub enabled: bool,
    /// MFA方法
    pub method: Option<MfaMethod>,
    /// 备用代码剩余数量
    pub backup_codes_count: u32,
    /// 最后使用时间
    pub last_used_at: Option<DateTime<Utc>>,
}

/// 登录时的MFA要求响应
#[derive(Debug, Serialize)]
pub struct MfaRequiredResponse {
    /// 临时令牌（用于后续MFA验证）
    pub temp_token: String,
    /// 需要的MFA方法
    pub required_method: MfaMethod,
    /// 提示消息
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_mfa_creation() {
        let user_id = "test_user".to_string();
        let mfa = UserMfa::new(user_id.clone(), MfaMethod::Totp);

        assert_eq!(mfa.user_id, user_id);
        assert_eq!(mfa.status, MfaStatus::Disabled);
        assert_eq!(mfa.method, MfaMethod::Totp);
        assert!(mfa.totp_secret.is_none());
        assert!(mfa.backup_codes.is_empty());
    }

    #[test]
    fn test_backup_codes_generation() {
        let codes = UserMfa::generate_backup_codes();
        
        assert_eq!(codes.len(), 8);
        
        // 检查每个代码都是8位大写字母数字
        for code in codes {
            assert_eq!(code.len(), 8);
            assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
            assert!(code.chars().all(|c| c.is_uppercase() || c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_enable_totp_request_validation() {
        use validator::Validate;
        
        let valid_request = EnableTotpRequest {
            totp_code: "123456".to_string(),
        };
        assert!(valid_request.validate().is_ok());

        let invalid_request = EnableTotpRequest {
            totp_code: "12345".to_string(), // 太短
        };
        assert!(invalid_request.validate().is_err());

        let invalid_request2 = EnableTotpRequest {
            totp_code: "1234567".to_string(), // 太长
        };
        assert!(invalid_request2.validate().is_err());
    }
}
