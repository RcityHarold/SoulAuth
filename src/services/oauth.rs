use crate::{
    config::Config,
    error::{AuthError, Result},
    models::identity_provider::OAuthUserInfo,
};
use oauth2::{
    basic::BasicClient,
    reqwest::async_http_client,
    AuthUrl,
    ClientId,
    ClientSecret,
    RedirectUrl,
    TokenUrl,
    Scope,
    CsrfToken,
    TokenResponse,
};
use serde::Deserialize;
use tracing::{error, info};
use reqwest::{Client, Proxy};

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
    verified_email: bool,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUserInfo {
    id: i64,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

pub struct OAuthService {
    config: Config,
    google_client: BasicClient,
    github_client: BasicClient,
}

#[cfg(test)]
mod tests {
    use super::OAuthService;
    use crate::config::Config;

    fn test_config() -> Config {
        Config {
            database_url: "http://localhost:8000".to_string(),
            database_user: "root".to_string(),
            database_pass: "root".to_string(),
            database_namespace: "auth".to_string(),
            database_name: "main".to_string(),
            database_connection_timeout: 30,
            database_max_connections: 10,
            jwt_secret: "test-secret".to_string(),
            jwt_expiration: 3600,
            google_client_id: "google-client".to_string(),
            google_client_secret: "google-secret".to_string(),
            github_client_id: "github-client".to_string(),
            github_client_secret: "github-secret".to_string(),
            oauth_redirect_url: "https://auth.example/api/auth/callback".to_string(),
            proxy_enabled: false,
            proxy_url: None,
            smtp_host: "localhost".to_string(),
            smtp_port: 1025,
            smtp_username: "smtp-user".to_string(),
            smtp_password: "smtp-pass".to_string(),
            smtp_from: "noreply@example.com".to_string(),
            smtp_insecure: true,
            app_url: "https://auth.example".to_string(),
            email_verification_enabled: false,
        }
    }

    #[test]
    fn google_auth_url_can_preserve_oidc_return_token_in_state() {
        let service = OAuthService::new(test_config()).expect("service");
        let oidc_return_token = "eyJhbGciOiJIUzI1NiJ9.oidc-return.sig";

        let url = service
            .get_google_auth_url_with_state(Some(oidc_return_token))
            .expect("auth url");

        assert!(url.contains("state=eyJhbGciOiJIUzI1NiJ9.oidc-return.sig"));
    }
}

impl OAuthService {
    pub fn new(config: Config) -> Result<Self> {
        let google_client = BasicClient::new(
            ClientId::new(config.google_client_id.clone()),
            Some(ClientSecret::new(config.google_client_secret.clone())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            Some(
                TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                    .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/google", config.oauth_redirect_url))
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
        );

        let github_client = BasicClient::new(
            ClientId::new(config.github_client_id.clone()),
            Some(ClientSecret::new(config.github_client_secret.clone())),
            AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            Some(
                TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
                    .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/github", config.oauth_redirect_url))
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
        );

        Ok(Self {
            config,
            google_client,
            github_client,
        })
    }

    // 创建一个配置了代理的 HTTP 客户端
    fn create_http_client(&self) -> Result<Client> {
        let mut client_builder = Client::builder()
            .danger_accept_invalid_certs(true);  // 允许自签名证书
        
        if self.config.proxy_enabled {
            if let Some(proxy_url) = &self.config.proxy_url {
                let proxy_url = proxy_url.replace("https://", "http://");  // 强制使用 http 协议
                info!("Using proxy: {}", proxy_url);
                client_builder = client_builder.proxy(
                    Proxy::all(&proxy_url)
                        .map_err(|e| AuthError::OAuthError(format!("Failed to create proxy: {}", e)))?
                );
            }
        }

        client_builder
            .build()
            .map_err(|e| AuthError::OAuthError(format!("Failed to create HTTP client: {}", e)))
    }

    pub fn get_google_auth_url(&self) -> Result<String> {
        self.get_google_auth_url_with_state(None)
    }

    pub fn get_google_auth_url_with_state(&self, state: Option<&str>) -> Result<String> {
        let csrf_token = state
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let (auth_url, _) = self.google_client
            .authorize_url(|| CsrfToken::new(csrf_token))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ))
            .url();

        Ok(auth_url.to_string())
    }

    pub async fn handle_google_callback(&self, code: String) -> Result<OAuthUserInfo> {
        info!("Starting Google OAuth callback with code: {}", code);
        
        // 交换授权码获取访问令牌
        info!("Exchanging authorization code for access token");
        let token = if self.config.proxy_enabled {
            let client = self.create_http_client()?;
            self.google_client
                .exchange_code(oauth2::AuthorizationCode::new(code))
                .request_async(async_http_client)
                .await
        } else {
            self.google_client
                .exchange_code(oauth2::AuthorizationCode::new(code))
                .request_async(async_http_client)
                .await
        }.map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 使用访问令牌获取用户信息
        info!("Fetching user info from Google API");
        let client = if self.config.proxy_enabled {
            self.create_http_client()?
        } else {
            Client::new()
        };

        let user_info: GoogleUserInfo = match client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(token.access_token().secret())
            .send()
            .await {
                Ok(response) => {
                    info!("Received response from Google API");
                    match response.json().await {
                        Ok(info) => {
                            info!("Successfully parsed user info");
                            info
                        },
                        Err(e) => {
                            error!("Failed to parse user info: {}", e);
                            return Err(AuthError::OAuthError(e.to_string()));
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to fetch user info: {}", e);
                    return Err(AuthError::OAuthError(e.to_string()));
                }
            };

        if !user_info.verified_email {
            error!("User email is not verified");
            return Err(AuthError::EmailNotVerified);
        }

        info!("Successfully completed Google OAuth callback for user: {}", user_info.email);
        Ok(OAuthUserInfo {
            provider: "google".to_string(),
            provider_user_id: user_info.id,
            email: user_info.email,
            name: user_info.name,
            picture: user_info.picture,
        })
    }

    pub fn get_github_auth_url(&self) -> Result<String> {
        let (auth_url, _) = self
            .github_client
            .authorize_url(|| CsrfToken::new(uuid::Uuid::new_v4().to_string()))
            .add_scope(Scope::new("user:email".to_string()))
            .url();

        Ok(auth_url.to_string())
    }

    pub async fn handle_github_callback(&self, code: String) -> Result<OAuthUserInfo> {
        // 交换授权码获取访问令牌
        let token = if self.config.proxy_enabled {
            let client = self.create_http_client()?;
            self.github_client
                .exchange_code(oauth2::AuthorizationCode::new(code))
                .request_async(async_http_client)
                .await
        } else {
            self.github_client
                .exchange_code(oauth2::AuthorizationCode::new(code))
                .request_async(async_http_client)
                .await
        }.map_err(|e| AuthError::OAuthError(e.to_string()))?;

        let client = if self.config.proxy_enabled {
            self.create_http_client()?
        } else {
            Client::new()
        };
        
        // 获取用户信息
        let user_info: GitHubUserInfo = client
            .get("https://api.github.com/user")
            .bearer_auth(token.access_token().secret())
            .header("User-Agent", "rust-auth-system")
            .send()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 获取用户邮箱（因为某些用户可能没有公开邮箱）
        let emails: Vec<GitHubEmail> = client
            .get("https://api.github.com/user/emails")
            .bearer_auth(token.access_token().secret())
            .header("User-Agent", "rust-auth-system")
            .send()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 获取主要且已验证的邮箱
        let primary_email = emails
            .into_iter()
            .find(|e| e.primary && e.verified)
            .ok_or_else(|| AuthError::EmailNotVerified)?;

        Ok(OAuthUserInfo {
            provider: "github".to_string(),
            provider_user_id: user_info.id.to_string(),
            email: primary_email.email,
            name: user_info.name,
            picture: user_info.avatar_url,
        })
    }
}
