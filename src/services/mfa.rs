use crate::{
    config::Config,
    error::{AuthError, Result},
    models::mfa::{
        UserMfa, MfaStatus, MfaMethod, TotpSetupResponse, MfaVerificationResponse, 
        MfaStatusResponse, EnableTotpRequest, VerifyTotpRequest, UseBackupCodeRequest
    },
    services::database::Database,
    utils::crypto::{hash_backup_code, verify_backup_code, SecretCipher},
};
use chrono::Utc;
use qrcode::{QrCode, render::svg};
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP, Secret};
use tracing::{info, error, debug};

/// MFA服务
pub struct MfaService {
    db: Database,
    /// TOTP 密钥的静态加密器。
    cipher: SecretCipher,
}

impl MfaService {
    /// 创建新的MFA服务实例
    pub fn new(db: Arc<Database>, config: Config) -> Result<Self> {
        Ok(Self {
            db: (*db).clone(),
            cipher: SecretCipher::from_config(&config)?,
        })
    }

    /// 为用户初始化TOTP设置
    pub async fn setup_totp(&self, user_id: &str) -> Result<TotpSetupResponse> {
        info!("Setting up TOTP for user: {}", user_id);

        // 检查用户是否已经启用MFA
        if let Ok(existing_mfa) = self.get_user_mfa(user_id).await {
            if existing_mfa.status == MfaStatus::Enabled {
                return Err(AuthError::ServerError("MFA already enabled".to_string()));
            }
        }

        // 生成TOTP密钥。
        // 注意 rng 必须在 await 之前析构：ThreadRng 不是 Send，
        // 跨 await 持有会让整个 handler future 变成 !Send，路由注册直接编译不过。
        let secret_bytes: Vec<u8> = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            (0..20).map(|_| rng.gen()).collect()
        };
        let secret_str = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);
        let secret = Secret::Encoded(secret_str.clone());

        // 创建TOTP实例
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            Some("RustAuth".to_string()),
            user_id.to_string(),
        )?;

        // 生成QR码
        let qr_code_url = totp.get_url();
        let qr_code = QrCode::new(&qr_code_url)
            .map_err(|e| AuthError::ServerError(format!("Failed to generate QR code: {}", e)))?;
        
        let qr_svg = qr_code
            .render::<svg::Color>()
            .min_dimensions(200, 200)
            .build();

        // 转换为数据URL
        use base64::{Engine as _, engine::general_purpose};
        let qr_data_url = format!("data:image/svg+xml;base64,{}", general_purpose::STANDARD.encode(qr_svg));

        // 生成备用恢复代码：明文只在这一次返回给用户，库里存 Argon2 哈希。
        let backup_codes = UserMfa::generate_backup_codes();
        let hashed_backup_codes = backup_codes
            .iter()
            .map(|code| hash_backup_code(code))
            .collect::<Result<Vec<_>>>()?;

        // 保存MFA配置到数据库（状态为Pending）
        let mfa_config = UserMfa {
            user_id: user_id.to_string(),
            status: MfaStatus::Pending,
            method: MfaMethod::Totp,
            totp_secret: Some(self.cipher.encrypt(&secret_str)?),
            backup_codes: hashed_backup_codes,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_used_at: None,
        };

        self.save_user_mfa(&mfa_config).await?;

        info!("TOTP setup completed for user: {}", user_id);

        Ok(TotpSetupResponse {
            secret: secret_str,
            qr_code: qr_data_url,
            backup_codes,
        })
    }

    /// 启用TOTP（验证初始化时的代码）
    pub async fn enable_totp(&self, user_id: &str, request: EnableTotpRequest) -> Result<bool> {
        info!("Enabling TOTP for user: {}", user_id);

        // 获取用户MFA配置
        let mut mfa_config = self.get_user_mfa(user_id).await?;
        
        if mfa_config.status != MfaStatus::Pending {
            return Err(AuthError::ServerError("TOTP not in pending state".to_string()));
        }

        let secret = self.decrypted_secret(&mfa_config)?;

        // 验证TOTP代码
        if self.verify_totp_code(&secret, &request.totp_code)? {
            // 更新状态为已启用
            mfa_config.status = MfaStatus::Enabled;
            mfa_config.updated_at = Utc::now();
            mfa_config.last_used_at = Some(Utc::now());

            self.save_user_mfa(&mfa_config).await?;

            info!("TOTP enabled successfully for user: {}", user_id);
            Ok(true)
        } else {
            error!("Invalid TOTP code for user: {}", user_id);
            Ok(false)
        }
    }

    /// 验证TOTP代码
    pub async fn verify_totp(&self, user_id: &str, request: VerifyTotpRequest) -> Result<MfaVerificationResponse> {
        debug!("Verifying TOTP for user: {}", user_id);

        let mut mfa_config = self.get_user_mfa(user_id).await?;
        
        if mfa_config.status != MfaStatus::Enabled {
            return Ok(MfaVerificationResponse {
                verified: false,
                token: None,
                message: Some("MFA not enabled".to_string()),
            });
        }

        let secret = self.decrypted_secret(&mfa_config)?;

        if self.verify_totp_code(&secret, &request.totp_code)? {
            // 更新最后使用时间
            mfa_config.last_used_at = Some(Utc::now());
            self.save_user_mfa(&mfa_config).await?;

            info!("TOTP verification successful for user: {}", user_id);
            
            Ok(MfaVerificationResponse {
                verified: true,
                token: None, // 将在上层生成JWT token
                message: None,
            })
        } else {
            error!("Invalid TOTP code for user: {}", user_id);
            
            Ok(MfaVerificationResponse {
                verified: false,
                token: None,
                message: Some("Invalid TOTP code".to_string()),
            })
        }
    }

    /// 使用备用恢复代码
    pub async fn use_backup_code(&self, user_id: &str, request: UseBackupCodeRequest) -> Result<MfaVerificationResponse> {
        info!("Using backup code for user: {}", user_id);

        let mut mfa_config = self.get_user_mfa(user_id).await?;
        
        if mfa_config.status != MfaStatus::Enabled {
            return Ok(MfaVerificationResponse {
                verified: false,
                token: None,
                message: Some("MFA not enabled".to_string()),
            });
        }

        // 逐条哈希比对；命中即消费掉该条。
        let hit = mfa_config
            .backup_codes
            .iter()
            .position(|stored| verify_backup_code(stored, &request.backup_code));

        if let Some(index) = hit {
            // 移除已使用的备用代码
            mfa_config.backup_codes.remove(index);
            mfa_config.last_used_at = Some(Utc::now());
            mfa_config.updated_at = Utc::now();

            self.save_user_mfa(&mfa_config).await?;

            info!("Backup code used successfully for user: {}", user_id);
            
            Ok(MfaVerificationResponse {
                verified: true,
                token: None, // 将在上层生成JWT token
                message: None,
            })
        } else {
            error!("Invalid backup code for user: {}", user_id);
            
            Ok(MfaVerificationResponse {
                verified: false,
                token: None,
                message: Some("Invalid backup code".to_string()),
            })
        }
    }

    /// 禁用MFA
    pub async fn disable_mfa(&self, user_id: &str) -> Result<bool> {
        info!("Disabling MFA for user: {}", user_id);

        let mfa_config = self.get_user_mfa(user_id).await?;
        
        if mfa_config.status == MfaStatus::Disabled {
            return Ok(true);
        }

        // 删除MFA配置
        self.delete_user_mfa(user_id).await?;

        info!("MFA disabled successfully for user: {}", user_id);
        Ok(true)
    }

    /// 获取用户MFA状态
    pub async fn get_mfa_status(&self, user_id: &str) -> Result<MfaStatusResponse> {
        match self.get_user_mfa(user_id).await {
            Ok(mfa_config) => {
                Ok(MfaStatusResponse {
                    enabled: mfa_config.status == MfaStatus::Enabled,
                    method: Some(mfa_config.method),
                    backup_codes_count: mfa_config.backup_codes.len() as u32,
                    last_used_at: mfa_config.last_used_at,
                })
            }
            Err(AuthError::UserNotFound) => {
                Ok(MfaStatusResponse {
                    enabled: false,
                    method: None,
                    backup_codes_count: 0,
                    last_used_at: None,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// 返回用户已启用的 MFA 方式；没有配置则返回 `Ok(None)`。
    ///
    /// 登录链路用它决定是否要走两步验证，因此**必须 fail-closed**：
    /// 查询出错时返回 Err 让登录直接失败，而不是当作"未启用 MFA"放行 ——
    /// 否则一次数据库抖动就等于对所有账号临时关闭了二次验证。
    pub async fn enabled_method(&self, user_id: &str) -> Result<Option<MfaMethod>> {
        match self.get_user_mfa(user_id).await {
            Ok(config) if config.status == MfaStatus::Enabled => Ok(Some(config.method)),
            Ok(_) => Ok(None),
            Err(AuthError::UserNotFound) => Ok(None),
            Err(e) => {
                error!("Failed to load MFA config for user {}: {:?}", user_id, e);
                Err(e)
            }
        }
    }

    /// 取出并解密 TOTP 密钥。
    ///
    /// 兼容升级前写入的明文记录：`SecretCipher::decrypt` 对无密文前缀的值原样返回，
    /// 这些记录会在下一次 `save_user_mfa` 时被自动加密（见 `save_user_mfa`）。
    fn decrypted_secret(&self, mfa_config: &UserMfa) -> Result<String> {
        let stored = mfa_config
            .totp_secret
            .as_ref()
            .ok_or_else(|| AuthError::ServerError("TOTP secret not found".to_string()))?;

        self.cipher.decrypt(stored)
    }

    /// 验证TOTP代码
    fn verify_totp_code(&self, secret: &str, code: &str) -> Result<bool> {
        let secret_bytes = Secret::Encoded(secret.to_string())
            .to_bytes()
            .map_err(|e| AuthError::ServerError(format!("Invalid secret: {}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("RustAuth".to_string()),
            "".to_string(),
        ).map_err(|e| AuthError::ServerError(format!("TOTP creation failed: {}", e)))?;

        Ok(totp.check_current(code).map_err(|e| {
            AuthError::ServerError(format!("TOTP verification failed: {}", e))
        })?)
    }

    /// 从数据库获取用户MFA配置
    async fn get_user_mfa(&self, user_id: &str) -> Result<UserMfa> {
        let mut result = self
            .db
            .raw_query(
                "mfa_get_user_config",
                "SELECT * FROM user_mfa WHERE user_id = $user_id LIMIT 1",
                serde_json::json!({ "user_id": user_id }),
            )
            .await?;

        let mfa_config: Option<UserMfa> = result.take(0)?;

        mfa_config.ok_or(AuthError::UserNotFound)
    }

    /// 保存用户MFA配置到数据库。
    ///
    /// 写入前统一把 TOTP 密钥转成密文 —— 存量的明文记录只要经过任意一次
    /// 保存（启用、验证、用备用码）就会被就地加密。
    /// 注意：`raw_query` 用 JSON 绑定，`DateTime` 会序列化成 RFC3339 字符串，
    /// 而 `user_mfa` 的时间列是 `datetime` —— SCHEMAFULL 不会自动强转，
    /// 必须在语句里显式 `type::datetime()`，并兼容 `Option::None` 的 NULL。
    async fn save_user_mfa(&self, mfa_config: &UserMfa) -> Result<()> {
        let mfa_config = &self.with_encrypted_secret(mfa_config)?;
        let query = r#"
            UPSERT type::record('user_mfa', $user_id) CONTENT {
                user_id: $user_id,
                status: $status,
                method: $method,
                totp_secret: $totp_secret,
                backup_codes: $backup_codes,
                created_at: type::datetime($created_at),
                updated_at: type::datetime($updated_at),
                last_used_at: IF $last_used_at = NONE OR $last_used_at = NULL {
                    NONE
                } ELSE {
                    type::datetime($last_used_at)
                }
            }
        "#;

        self.db
            .raw_query(
                "mfa_save_user_config",
                query,
                serde_json::json!({
                    "user_id": mfa_config.user_id,
                    "status": mfa_config.status,
                    "method": mfa_config.method,
                    "totp_secret": mfa_config.totp_secret,
                    "backup_codes": mfa_config.backup_codes,
                    "created_at": mfa_config.created_at,
                    "updated_at": mfa_config.updated_at,
                    "last_used_at": mfa_config.last_used_at,
                }),
            )
            .await?;

        Ok(())
    }

    fn with_encrypted_secret(&self, mfa_config: &UserMfa) -> Result<UserMfa> {
        let mut config = mfa_config.clone();
        if let Some(secret) = &config.totp_secret {
            if !SecretCipher::is_encrypted(secret) {
                config.totp_secret = Some(self.cipher.encrypt(secret)?);
            }
        }
        Ok(config)
    }

    /// 删除用户MFA配置
    async fn delete_user_mfa(&self, user_id: &str) -> Result<()> {
        self.db
            .raw_query(
                "mfa_delete_user_config",
                "DELETE user_mfa WHERE user_id = $user_id",
                serde_json::json!({ "user_id": user_id }),
            )
            .await?;

        Ok(())
    }
}

// 为TOTP相关错误实现From trait
impl From<totp_rs::TotpUrlError> for AuthError {
    fn from(err: totp_rs::TotpUrlError) -> Self {
        AuthError::ServerError(format!("TOTP URL error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_totp_code_verification() {
        // 创建MFA服务实例用于测试
        // 注意：这需要有效的数据库配置，在实际测试中可能需要模拟
        
        // 测试TOTP代码验证逻辑
        let secret = Secret::Raw((0u8..20).collect());
        
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            Some("RustAuth".to_string()),
            "test@example.com".to_string(),
        ).unwrap();
        
        let code = totp.generate_current().unwrap();
        
        // 验证生成的代码应该是有效的
        assert!(totp.check_current(&code).unwrap());
    }

    #[test]
    fn test_backup_codes_generation() {
        let codes = UserMfa::generate_backup_codes();
        
        assert_eq!(codes.len(), 8);
        
        for code in &codes {
            assert_eq!(code.len(), 8);
            assert!(code.chars().all(|c| c.is_ascii_alphanumeric() && c.is_uppercase()));
        }
        
        // 确保代码是唯一的
        let mut unique_codes = codes.clone();
        unique_codes.sort();
        unique_codes.dedup();
        assert_eq!(unique_codes.len(), codes.len());
    }
}
