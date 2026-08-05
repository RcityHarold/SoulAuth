use serde::Deserialize;
use std::env;

/// 配置读取错误。
///
/// 以前这里对所有必填项直接 `expect` 导致进程 panic，堆栈里看不出到底缺哪个变量。
/// 现在统一走 `ConfigError`，由 `main` 打印后正常退出。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing required environment variable: {0}")]
    Missing(&'static str),
    #[error("Invalid value for environment variable {name}: {reason}")]
    Invalid { name: &'static str, reason: String },
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub database_user: String,
    pub database_pass: String,
    pub database_namespace: String,
    pub database_name: String,
    pub database_connection_timeout: u64,
    pub database_max_connections: u32,
    pub jwt_secret: String,
    pub jwt_expiration: i64,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub oauth_redirect_url: String,
    // 代理配置
    pub proxy_enabled: bool,
    pub proxy_url: Option<String>,
    // 邮件配置
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from: String,
    pub smtp_insecure: bool,
    pub app_url: String,
    pub email_verification_enabled: bool,
    /// 是否信任 `X-Forwarded-For` / `X-Real-IP`。
    /// 只有当服务确实跑在受控反向代理之后时才应打开：否则客户端可以任意伪造
    /// 来源 IP，从而绕过限流与 IP 维度的账号锁定。
    pub trust_proxy_headers: bool,
    /// CORS 白名单。为空表示只允许 `app_url` 自身。
    pub cors_allowed_origins: Vec<String>,
    /// OIDC ID Token 的 RSA 私钥（PEM，PKCS#8 或 PKCS#1）。
    pub oidc_rsa_private_key_pem: Option<String>,
    /// OIDC ID Token 的 RSA 私钥文件路径，与上面的 PEM 二选一。
    pub oidc_rsa_private_key_path: Option<String>,
    /// 密码最小长度。
    pub password_min_length: usize,
    /// MFA TOTP 密钥的加密密钥（base64 编码的 32 字节）。
    /// 不配置时从 `jwt_secret` 派生，并在启动时告警。
    pub mfa_encryption_key: Option<String>,
    /// 前端登录页地址。`/api/oidc/authorize` 在用户未登录时跳到这里。
    /// 不配置时默认 `{app_url}/login`。
    pub login_page_url: Option<String>,
    /// 邮箱验证页地址（验证邮件里的链接指向它）。
    /// 不配置时默认 `{app_url}/verify-email`。
    pub verify_email_page_url: Option<String>,
    /// 已认证请求的会话校验缓存时长（秒）。0 表示关闭缓存。
    pub session_cache_ttl_seconds: u64,
    /// 启动前需要等待的安装标记文件；不配置则不等待。
    pub install_marker_path: Option<String>,
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_with_default<T: std::str::FromStr>(
    name: &'static str,
    default: T,
) -> Result<T, ConfigError> {
    match optional(name) {
        None => Ok(default),
        Some(raw) => raw.parse::<T>().map_err(|_| ConfigError::Invalid {
            name,
            reason: format!("cannot parse `{raw}`"),
        }),
    }
}

fn parse_bool(name: &str, default: bool) -> bool {
    optional(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let app_url = required("APP_URL")?;

        let cors_allowed_origins = optional("CORS_ALLOWED_ORIGINS")
            .map(|raw| {
                raw.split(',')
                    .map(|origin| origin.trim().trim_end_matches('/').to_string())
                    .filter(|origin| !origin.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let config = Self {
            database_url: optional("DATABASE_URL")
                .unwrap_or_else(|| "http://localhost:8000".to_string()),
            database_user: optional("DATABASE_USER").unwrap_or_else(|| "root".to_string()),
            database_pass: optional("DATABASE_PASS").unwrap_or_else(|| "root".to_string()),
            database_namespace: optional("DATABASE_NAMESPACE")
                .unwrap_or_else(|| "auth".to_string()),
            database_name: optional("DATABASE_NAME").unwrap_or_else(|| "main".to_string()),
            database_connection_timeout: parse_with_default("DATABASE_CONNECTION_TIMEOUT", 30)?,
            database_max_connections: parse_with_default("DATABASE_MAX_CONNECTIONS", 10)?,
            jwt_secret: required("JWT_SECRET")?,
            jwt_expiration: parse_with_default("JWT_EXPIRATION", 86_400)?,
            google_client_id: required("GOOGLE_CLIENT_ID")?,
            google_client_secret: required("GOOGLE_CLIENT_SECRET")?,
            github_client_id: required("GITHUB_CLIENT_ID")?,
            github_client_secret: required("GITHUB_CLIENT_SECRET")?,
            oauth_redirect_url: required("OAUTH_REDIRECT_URL")?,
            proxy_enabled: parse_bool("PROXY_ENABLED", false),
            proxy_url: optional("PROXY_URL"),
            smtp_host: required("SMTP_HOST")?,
            smtp_port: parse_with_default("SMTP_PORT", 587u16)?,
            smtp_username: env::var("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: env::var("SMTP_PASSWORD").unwrap_or_default(),
            smtp_from: required("SMTP_FROM")?,
            smtp_insecure: parse_bool("SMTP_INSECURE", false),
            app_url,
            email_verification_enabled: parse_bool("EMAIL_VERIFICATION_ENABLED", false),
            trust_proxy_headers: parse_bool("TRUST_PROXY_HEADERS", false),
            cors_allowed_origins,
            oidc_rsa_private_key_pem: optional("OIDC_RSA_PRIVATE_KEY_PEM"),
            oidc_rsa_private_key_path: optional("OIDC_RSA_PRIVATE_KEY_PATH"),
            password_min_length: parse_with_default("PASSWORD_MIN_LENGTH", 12usize)?,
            mfa_encryption_key: optional("MFA_SECRET_ENCRYPTION_KEY"),
            login_page_url: optional("LOGIN_PAGE_URL"),
            verify_email_page_url: optional("VERIFY_EMAIL_PAGE_URL"),
            session_cache_ttl_seconds: parse_with_default("AUTH_SESSION_CACHE_TTL_SECONDS", 5u64)?,
            install_marker_path: optional("INSTALL_MARKER_PATH"),
        };

        if config.jwt_secret.len() < 32 {
            return Err(ConfigError::Invalid {
                name: "JWT_SECRET",
                reason: "must be at least 32 characters".to_string(),
            });
        }

        Ok(config)
    }

    /// Cookie 是否应带 `Secure`。
    ///
    /// 恒定带 `Secure` 会让 `http://localhost` 的本地开发完全跑不通（浏览器
    /// 直接丢弃 cookie，OIDC 流程走不下去）。这里按部署协议决定：
    /// `app_url` 是 https 就带，否则不带。
    pub fn cookies_secure(&self) -> bool {
        self.app_url.trim().to_ascii_lowercase().starts_with("https://")
    }

    /// 未登录用户从 `/api/oidc/authorize` 被引导去的登录页。
    pub fn login_page_url(&self) -> String {
        self.login_page_url.clone().unwrap_or_else(|| {
            format!("{}/login", self.app_url.trim_end_matches('/'))
        })
    }

    /// 验证邮件里链接指向的前端页面。
    pub fn verify_email_page_url(&self) -> String {
        self.verify_email_page_url.clone().unwrap_or_else(|| {
            format!("{}/verify-email", self.app_url.trim_end_matches('/'))
        })
    }

    /// CORS 允许的来源列表：显式白名单优先，否则回落到自身 `app_url`。
    pub fn effective_cors_origins(&self) -> Vec<String> {
        if self.cors_allowed_origins.is_empty() {
            vec![self.app_url.trim_end_matches('/').to_string()]
        } else {
            self.cors_allowed_origins.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn config_with_app_url(app_url: &str) -> Config {
        Config {
            database_url: "http://localhost:8000".to_string(),
            database_user: "root".to_string(),
            database_pass: "root".to_string(),
            database_namespace: "auth".to_string(),
            database_name: "main".to_string(),
            database_connection_timeout: 30,
            database_max_connections: 10,
            jwt_secret: "0123456789abcdef0123456789abcdef".to_string(),
            jwt_expiration: 3600,
            google_client_id: "g".to_string(),
            google_client_secret: "g".to_string(),
            github_client_id: "h".to_string(),
            github_client_secret: "h".to_string(),
            oauth_redirect_url: "https://auth.example/api/auth/callback".to_string(),
            proxy_enabled: false,
            proxy_url: None,
            smtp_host: "localhost".to_string(),
            smtp_port: 1025,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_from: "noreply@example.com".to_string(),
            smtp_insecure: true,
            app_url: app_url.to_string(),
            email_verification_enabled: false,
            trust_proxy_headers: false,
            cors_allowed_origins: Vec::new(),
            oidc_rsa_private_key_pem: None,
            oidc_rsa_private_key_path: None,
            password_min_length: 12,
            mfa_encryption_key: None,
            login_page_url: None,
            verify_email_page_url: None,
            session_cache_ttl_seconds: 5,
            install_marker_path: None,
        }
    }

    #[test]
    fn cookies_are_secure_only_over_https() {
        assert!(config_with_app_url("https://auth.example").cookies_secure());
        assert!(!config_with_app_url("http://localhost:8080").cookies_secure());
    }

    #[test]
    fn login_page_defaults_to_app_url_login() {
        assert_eq!(
            config_with_app_url("https://auth.example/").login_page_url(),
            "https://auth.example/login"
        );
    }

    #[test]
    fn cors_falls_back_to_app_url() {
        assert_eq!(
            config_with_app_url("https://auth.example/").effective_cors_origins(),
            vec!["https://auth.example".to_string()]
        );
    }
}
