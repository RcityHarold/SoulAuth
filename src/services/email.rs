use crate::{config::Config, error::{AuthError, Result}};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::time::Duration;

pub struct EmailService {
    config: Config,
}

impl EmailService {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    fn create_transport(&self) -> Result<SmtpTransport> {
        let creds = Credentials::new(
            self.config.smtp_username.clone(),
            self.config.smtp_password.clone(),
        );

        // 如果启用了代理，设置环境变量
        if self.config.proxy_enabled {
            if let Some(proxy_url) = &self.config.proxy_url {
                // 为当前进程设置代理环境变量
                std::env::set_var("HTTPS_PROXY", proxy_url);
                std::env::set_var("HTTP_PROXY", proxy_url);
                std::env::set_var("https_proxy", proxy_url);
                std::env::set_var("http_proxy", proxy_url);
                
                tracing::info!("设置代理环境变量: {}", proxy_url);
            }
        }

        let transport = if self.config.smtp_insecure {
            SmtpTransport::builder_dangerous(&self.config.smtp_host)
                .port(self.config.smtp_port)
                .credentials(creds)
                .timeout(Some(Duration::from_secs(60)))
                .build()
        } else {
            SmtpTransport::starttls_relay(&self.config.smtp_host)
                .map_err(|e| AuthError::ServerError(format!("Failed to create SMTP transport: {}", e)))?
                .port(self.config.smtp_port)
                .credentials(creds)
                .timeout(Some(Duration::from_secs(60)))
                .build()
        };

        Ok(transport)
    }

    pub async fn send_verification_email(&self, to_email: &str, token: &str) -> Result<()> {
        let from_address = self.config.smtp_from.parse::<Mailbox>()
            .map_err(|e| AuthError::ServerError(format!("Invalid from address: {}", e)))?;
        
        let to_address = to_email.parse::<Mailbox>()
            .map_err(|e| AuthError::ServerError(format!("Invalid to address: {}", e)))?;

        let verification_link = format!("{}/api/auth/verify-email/{}", self.config.app_url, token);

        let email = Message::builder()
            .from(from_address)
            .to(to_address)
            .subject("Verify your email address")
            .header(ContentType::TEXT_HTML)
            .body(format!(
                r#"
                <h1>Welcome!</h1>
                <p>Please click the link below to verify your email address:</p>
                <p><a href="{}">Verify Email</a></p>
                <p>If you didn't create an account, you can safely ignore this email.</p>
                "#,
                verification_link
            ))
            .map_err(|e| AuthError::ServerError(format!("Failed to build email: {}", e)))?;

        let transport = self.create_transport()?;
        transport
            .send(&email)
            .map_err(|e| AuthError::ServerError(format!("Failed to send email: {}", e)))?;

        Ok(())
    }

    pub async fn send_password_reset_email(&self, to_email: &str, token: &str) -> Result<()> {
        let from_address = self.config.smtp_from.parse::<Mailbox>()
            .map_err(|e| AuthError::ServerError(format!("Invalid from address: {}", e)))?;
        
        let to_address = to_email.parse::<Mailbox>()
            .map_err(|e| AuthError::ServerError(format!("Invalid to address: {}", e)))?;

        let reset_link = format!("{}/reset-password/{}", self.config.app_url, token);

        let email = Message::builder()
            .from(from_address)
            .to(to_address)
            .subject("Reset your password")
            .header(ContentType::TEXT_HTML)
            .body(format!(
                r#"
                <h1>Password Reset Request</h1>
                <p>You have requested to reset your password. Click the link below to set a new password:</p>
                <p><a href="{}">Reset Password</a></p>
                <p>If you didn't request this, you can safely ignore this email.</p>
                <p>This link will expire in 1 hour.</p>
                "#,
                reset_link
            ))
            .map_err(|e| AuthError::ServerError(format!("Failed to build email: {}", e)))?;

        let transport = self.create_transport()?;
        transport
            .send(&email)
            .map_err(|e| AuthError::ServerError(format!("Failed to send email: {}", e)))?;

        Ok(())
    }
}
