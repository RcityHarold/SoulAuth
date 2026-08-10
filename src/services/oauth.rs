use crate::{
    config::Config,
    error::{AuthError, Result},
    models::identity_provider::OAuthUserInfo,
};
use oauth2::{
    basic::BasicClient,
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

/// 出站 OAuth 请求的整体超时（含 TLS 握手、发送、读完响应体）。
const OUTBOUND_HTTP_TIMEOUT_SECS: u64 = 15;
/// 单独的建连超时，比整体超时短，让"连不上"比"响应慢"更快失败。
const OUTBOUND_CONNECT_TIMEOUT_SECS: u64 = 5;

pub struct OAuthService {
    config: Config,
    google_client: BasicClient,
    github_client: BasicClient,
    // 授权 / 换令牌两个端点已经进了 BasicClient，不必重复保存；
    // 这三个是「换到令牌之后」才用的，得自己拿着。
    google_userinfo_url: String,
    github_user_url: String,
    github_emails_url: String,
}

#[cfg(test)]
mod tests {
    use super::OAuthService;
    use crate::config::Config;

    fn test_config() -> Config {
        Config::test_default()
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
    fn endpoint_overrides_keep_each_providers_real_path_shape() {
        // 覆盖之所以只给一个根地址，前提就是路径形状照抄真实 provider；
        // 形状一旦被改歪，本地替身就不再是忠实替身，测过也说明不了什么。
        let (auth, token, userinfo) = super::google_endpoints(Some("http://127.0.0.1:8126"));
        assert_eq!(auth, "http://127.0.0.1:8126/o/oauth2/v2/auth");
        assert_eq!(token, "http://127.0.0.1:8126/token");
        assert_eq!(userinfo, "http://127.0.0.1:8126/oauth2/v2/userinfo");

        // GitHub 覆盖后的路径正是 GitHub Enterprise 的约定
        let (auth, token, user, emails) = super::github_endpoints(Some("https://ghe.example.com"));
        assert_eq!(auth, "https://ghe.example.com/login/oauth/authorize");
        assert_eq!(token, "https://ghe.example.com/login/oauth/access_token");
        assert_eq!(user, "https://ghe.example.com/api/v3/user");
        assert_eq!(emails, "https://ghe.example.com/api/v3/user/emails");
    }

    #[test]
    fn without_override_the_official_endpoints_are_used() {
        // 防的是「加了覆盖能力，结果默认路径也被顺手改掉」。
        let (auth, token, userinfo) = super::google_endpoints(None);
        assert_eq!(auth, "https://accounts.google.com/o/oauth2/v2/auth");
        assert_eq!(token, "https://oauth2.googleapis.com/token");
        assert_eq!(userinfo, "https://www.googleapis.com/oauth2/v2/userinfo");

        let (auth, token, user, emails) = super::github_endpoints(None);
        assert_eq!(auth, "https://github.com/login/oauth/authorize");
        assert_eq!(token, "https://github.com/login/oauth/access_token");
        assert_eq!(user, "https://api.github.com/user");
        assert_eq!(emails, "https://api.github.com/user/emails");
    }

    #[test]
    fn an_empty_override_is_treated_as_absent() {
        // `GOOGLE_OAUTH_BASE_URL=` 会读成 Some("")，若不当空处理，
        // 端点就变成 `/token` 这种没有主机名的地址，直接把换令牌打断。
        let mut config = test_config();
        config.google_oauth_base_url = Some("   ".to_string());
        let service = OAuthService::new(config).expect("service");
        assert_eq!(
            service.google_userinfo_url,
            "https://www.googleapis.com/oauth2/v2/userinfo"
        );
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

/// 各 provider 的端点。`base` 为 `None` 时用官方地址；为 `Some` 时
/// **沿用该 provider 真实的路径形状**，只换根地址 —— 这样本地替身是忠实
/// 替身，测出来的东西对真实端点同样成立。
///
/// 只在这一处知道路径形状：换 provider 或改端点都只动这里。
fn google_endpoints(base: Option<&str>) -> (String, String, String) {
    match base {
        Some(b) => (
            format!("{b}/o/oauth2/v2/auth"),
            format!("{b}/token"),
            format!("{b}/oauth2/v2/userinfo"),
        ),
        None => (
            "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            "https://oauth2.googleapis.com/token".to_string(),
            "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
        ),
    }
}

/// 返回 (auth, token, user, emails)。覆盖时的路径正是 GitHub Enterprise 的约定。
fn github_endpoints(base: Option<&str>) -> (String, String, String, String) {
    match base {
        Some(b) => (
            format!("{b}/login/oauth/authorize"),
            format!("{b}/login/oauth/access_token"),
            format!("{b}/api/v3/user"),
            format!("{b}/api/v3/user/emails"),
        ),
        None => (
            "https://github.com/login/oauth/authorize".to_string(),
            "https://github.com/login/oauth/access_token".to_string(),
            "https://api.github.com/user".to_string(),
            "https://api.github.com/user/emails".to_string(),
        ),
    }
}

impl OAuthService {
    pub fn new(config: Config) -> Result<Self> {
        let base = |v: &Option<String>| {
            v.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned)
        };
        let (google_auth, google_token, google_userinfo_url) =
            google_endpoints(base(&config.google_oauth_base_url).as_deref());
        let (github_auth, github_token, github_user_url, github_emails_url) =
            github_endpoints(base(&config.github_oauth_base_url).as_deref());

        let google_client = BasicClient::new(
            ClientId::new(config.google_client_id.clone()),
            Some(ClientSecret::new(config.google_client_secret.clone())),
            AuthUrl::new(google_auth).map_err(|e| AuthError::OAuthError(e.to_string()))?,
            Some(TokenUrl::new(google_token).map_err(|e| AuthError::OAuthError(e.to_string()))?),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/google", config.oauth_redirect_url))
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
        );

        let github_client = BasicClient::new(
            ClientId::new(config.github_client_id.clone()),
            Some(ClientSecret::new(config.github_client_secret.clone())),
            AuthUrl::new(github_auth).map_err(|e| AuthError::OAuthError(e.to_string()))?,
            Some(TokenUrl::new(github_token).map_err(|e| AuthError::OAuthError(e.to_string()))?),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/github", config.oauth_redirect_url))
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
        );

        Ok(Self {
            config,
            google_client,
            github_client,
            google_userinfo_url,
            github_user_url,
            github_emails_url,
        })
    }

    // 创建一个配置了代理的 HTTP 客户端
    //
    // 注意：这里**不能**打开 `danger_accept_invalid_certs` —— 那等于对 Google /
    // GitHub 的 TLS 连接放弃证书校验，任何能插到链路中间的人都可以拿到授权码与
    // 访问令牌。自签名证书的场景请把 CA 加进系统信任库。
    fn create_http_client(&self) -> Result<Client> {
        // reqwest 默认**不设**任何超时。Google / GitHub（或一个配歪了的代理）一旦
        // 把连接吊住，回调 handler 就永远不返回，请求会一直堆着占住 tokio 任务和
        // 连接。这里给整个请求封顶。
        let mut client_builder = Client::builder()
            .timeout(std::time::Duration::from_secs(OUTBOUND_HTTP_TIMEOUT_SECS))
            .connect_timeout(std::time::Duration::from_secs(OUTBOUND_CONNECT_TIMEOUT_SECS));

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
        // 不要把 `code` 打进日志：授权码就是凭证，日志往往会外发到集中式平台，
        // 谁能读日志谁就能在它过期前抢先兑换成访问令牌。
        info!("Exchanging Google authorization code for access token");
        // 两条路径（走代理 / 不走代理）都用 `create_http_client`。以前不走代理时
        // 用的是 `async_http_client` 和 `Client::new()`，它们各自 new 一个默认
        // client —— 默认**没有超时**，等于把上面那份超时配置绕开了。
        let client = self.create_http_client()?;

        let token = self
            .google_client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .request_async({
                let client = client.clone();
                move |req| http_client_request(client.clone(), req)
            })
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 使用访问令牌获取用户信息
        info!("Fetching user info from Google API");

        let user_info: GoogleUserInfo = match client
            .get(&self.google_userinfo_url)
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
        // 交换授权码获取访问令牌（同 Google：统一走带超时的 client）
        let client = self.create_http_client()?;

        let token = self
            .github_client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .request_async({
                let client = client.clone();
                move |req| http_client_request(client.clone(), req)
            })
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;


        // 获取用户信息
        let user_info: GitHubUserInfo = client
            .get(&self.github_user_url)
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
            .get(&self.github_emails_url)
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
