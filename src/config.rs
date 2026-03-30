use serde::Deserialize;
use std::env;

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
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let config = Self {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "http://localhost:8000".to_string()),
            database_user: env::var("DATABASE_USER")
                .unwrap_or_else(|_| "root".to_string()),
            database_pass: env::var("DATABASE_PASS")
                .unwrap_or_else(|_| "root".to_string()),
            database_namespace: env::var("DATABASE_NAMESPACE")
                .unwrap_or_else(|_| "auth".to_string()),
            database_name: env::var("DATABASE_NAME")
                .unwrap_or_else(|_| "main".to_string()),
            database_connection_timeout: env::var("DATABASE_CONNECTION_TIMEOUT")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            database_max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            jwt_secret: env::var("JWT_SECRET")
                .expect("JWT_SECRET must be set"),
            jwt_expiration: env::var("JWT_EXPIRATION")
                .unwrap_or_else(|_| "86400".to_string())
                .parse()
                .unwrap(),
            google_client_id: env::var("GOOGLE_CLIENT_ID")
                .expect("GOOGLE_CLIENT_ID must be set"),
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET")
                .expect("GOOGLE_CLIENT_SECRET must be set"),
            github_client_id: env::var("GITHUB_CLIENT_ID")
                .expect("GITHUB_CLIENT_ID must be set"),
            github_client_secret: env::var("GITHUB_CLIENT_SECRET")
                .expect("GITHUB_CLIENT_SECRET must be set"),
            oauth_redirect_url: env::var("OAUTH_REDIRECT_URL")
                .expect("OAUTH_REDIRECT_URL must be set"),
            // 代理配置
            proxy_enabled: env::var("PROXY_ENABLED")
                .map(|v| v.parse().unwrap_or(false))
                .unwrap_or(false),
            proxy_url: env::var("PROXY_URL").ok(),
            smtp_host: env::var("SMTP_HOST")
                .expect("SMTP_HOST must be set"),
            smtp_port: env::var("SMTP_PORT")
                .expect("SMTP_PORT must be set")
                .parse()
                .expect("SMTP_PORT must be a number"),
            smtp_username: env::var("SMTP_USERNAME")
                .expect("SMTP_USERNAME must be set"),
            smtp_password: env::var("SMTP_PASSWORD")
                .expect("SMTP_PASSWORD must be set"),
            smtp_from: env::var("SMTP_FROM")
                .expect("SMTP_FROM must be set"),
            smtp_insecure: env::var("SMTP_INSECURE")
                .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false),
            app_url: env::var("APP_URL")
                .expect("APP_URL must be set"),
            email_verification_enabled: env::var("EMAIL_VERIFICATION_ENABLED")
                .map(|v| v.parse().unwrap_or(false))
                .unwrap_or(false),
        };

        Ok(config)
    }
}
