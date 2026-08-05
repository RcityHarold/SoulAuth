use crate::{
    config::Config,
    error::{AuthError, Result},
    models::identity_provider::OAuthUserInfo,
};
use oauth2::{
    basic::BasicClient,
    reqwest::async_http_client,
    AuthUrl,
    HttpRequest,
    HttpResponse,
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
    // 注意：GitHub 的 /user 接口对隐藏邮箱的账号返回 email=null，
    // 所以邮箱一律从 /user/emails 取，这里不再声明该字段。
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}


/// 用指定的 `reqwest::Client` 执行 oauth2 的 HTTP 往返。
///
/// `oauth2::reqwest::async_http_client` 内部自己 new 一个 Client，拿不到我们的代理
/// 配置 —— 原来的代码虽然在 `proxy_enabled` 分支里建了带代理的 client，
/// 却仍然把 `async_http_client` 传给 `request_async`，那个 client 建完就被丢掉，
/// 于是 `PROXY_ENABLED=true` 完全不起作用（编译器一直用 unused variable 警告标着）。
async fn http_client_request(
    client: Client,
    request: HttpRequest,
) -> std::result::Result<HttpResponse, reqwest::Error> {
    let mut builder = client.request(request.method, request.url.as_str());
    for (name, value) in request.headers.iter() {
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    let response = builder.body(request.body).send().await?;

    let status_code = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?.to_vec();

    Ok(HttpResponse {
        status_code,
        headers,
        body,
    })
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
            jwt_secret: "0123456789abcdef0123456789abcdef".to_string(),
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
    fn google_auth_url_carries_the_supplied_signed_state() {
        let service = OAuthService::new(test_config()).expect("service");
        let signed_state = "eyJhbGciOiJIUzI1NiJ9.state.sig";

        let url = service
            .get_google_auth_url_with_state(signed_state)
            .expect("auth url");

        assert!(url.contains("state=eyJhbGciOiJIUzI1NiJ9.state.sig"));
    }

    #[test]
    fn github_auth_url_carries_the_supplied_signed_state() {
        let service = OAuthService::new(test_config()).expect("service");
        let signed_state = "eyJhbGciOiJIUzI1NiJ9.state.sig";

        let url = service
            .get_github_auth_url_with_state(signed_state)
            .expect("auth url");

        assert!(url.contains("state=eyJhbGciOiJIUzI1NiJ9.state.sig"));
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
    //
    // 注意：这里**不能**打开 `danger_accept_invalid_certs` —— 那等于对 Google /
    // GitHub 的 TLS 连接放弃证书校验，任何能插到链路中间的人都可以拿到授权码与
    // 访问令牌。自签名证书的场景请把 CA 加进系统信任库。
    fn create_http_client(&self) -> Result<Client> {
        let mut client_builder = Client::builder();
        
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

    /// 生成 Google 授权 URL。
    ///
    /// `state` 必须是调用方（`routes::oidc::create_oauth_state_token`）签发的令牌：
    /// 回调时会验签，以此实现真正的 CSRF 防护。以前这里自己生成一个随机
    /// `CsrfToken` 然后直接丢弃，回调侧根本没有可校验的东西。
    pub fn get_google_auth_url_with_state(&self, state: &str) -> Result<String> {
        let csrf_token = state.to_owned();
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
        let exchange = self
            .google_client
            .exchange_code(oauth2::AuthorizationCode::new(code));
        let token = if self.config.proxy_enabled {
            let client = self.create_http_client()?;
            exchange
                .request_async(move |req| http_client_request(client.clone(), req))
                .await
                .map_err(|e| AuthError::OAuthError(e.to_string()))?
        } else {
            exchange
                .request_async(async_http_client)
                .await
                .map_err(|e| AuthError::OAuthError(e.to_string()))?
        };

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

    /// 生成 GitHub 授权 URL，`state` 语义同 Google。
    pub fn get_github_auth_url_with_state(&self, state: &str) -> Result<String> {
        let csrf_token = state.to_owned();
        let (auth_url, _) = self
            .github_client
            .authorize_url(|| CsrfToken::new(csrf_token))
            .add_scope(Scope::new("user:email".to_string()))
            .url();

        Ok(auth_url.to_string())
    }

    pub async fn handle_github_callback(&self, code: String) -> Result<OAuthUserInfo> {
        // 交换授权码获取访问令牌
        let exchange = self
            .github_client
            .exchange_code(oauth2::AuthorizationCode::new(code));
        let token = if self.config.proxy_enabled {
            let client = self.create_http_client()?;
            exchange
                .request_async(move |req| http_client_request(client.clone(), req))
                .await
                .map_err(|e| AuthError::OAuthError(e.to_string()))?
        } else {
            exchange
                .request_async(async_http_client)
                .await
                .map_err(|e| AuthError::OAuthError(e.to_string()))?
        };

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
