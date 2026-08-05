use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Instant,
};

use axum::{http::HeaderValue, middleware, routing::Router, Extension};
use tokio::time::{interval, Duration};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod models;
mod routes;
mod services;
mod utils;

use crate::{
    config::Config,
    services::{
        account_lockout::AccountLockoutService,
        auth::AuthService,
        audit_logger::AuditLogger,
        auth_cache::AuthCache,
        database::Database,
        oidc::OidcService,
        oidc_client_management::OidcClientService,
        oidc_keys::OidcSigningKey,
        rate_limiter::{RateLimiter, RateLimitRules},
        sso_session_management::SsoSessionService,
    },
    utils::rate_limit_middleware::rate_limit_layer,
};

/// 进程启动时刻，供 `/api/audit/system-health` 报告真实运行时长。
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

/// 已运行秒数；未初始化时返回 0（而不是以前写死的 3600）。
pub fn process_uptime_seconds() -> i64 {
    PROCESS_START
        .get()
        .map(|start| start.elapsed().as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub rate_limiter: Arc<RateLimiter>,
    pub lockout_service: Arc<AccountLockoutService>,
}

/// 可选的安装等待：只有显式配置 `INSTALL_MARKER_PATH` 时才阻塞启动。
///
/// 以前这里无条件轮询 `../Rainbow-docs/.rainbow_docs_installed`，把认证服务
/// 和另一个仓库的部署流程死绑在了一起。
async fn wait_for_install_marker(marker: &str) {
    if std::path::Path::new(marker).exists() {
        return;
    }

    info!("Waiting for install marker at {marker} ...");
    loop {
        if std::path::Path::new(marker).exists() {
            info!("Install marker found, continuing startup");
            return;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn build_cors_layer(config: &Config) -> CorsLayer {
    // 以前是 allow_origin(Any) + allow_headers(Any)：任何站点都能带着用户的
    // Authorization 头调用本服务。现在收敛成显式白名单。
    let origins: Vec<HeaderValue> = config
        .effective_cors_origins()
        .iter()
        .filter_map(|origin| match HeaderValue::from_str(origin) {
            Ok(value) => Some(value),
            Err(_) => {
                warn!("Ignoring invalid CORS origin: {origin}");
                None
            }
        })
        .collect();

    info!("CORS allowed origins: {:?}", config.effective_cors_origins());

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
        .allow_credentials(true)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "rust_auth=debug,tower_http=info".to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let _ = PROCESS_START.set(Instant::now());
    info!("Starting auth service...");

    dotenv::dotenv().ok();
    let config = Config::from_env()?;

    if let Some(marker) = config.install_marker_path.clone() {
        wait_for_install_marker(&marker).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    // 数据库 schema 由 schema.sql / initial_data.sql 负责，应用本身不做 DDL。
    let db = Database::new(&config).await?;
    db.verify_connection().await?;
    info!(
        "Database connection established. Ensure schema.sql and initial_data.sql have been applied."
    );

    let shared_db = Arc::new(db.clone());

    let rate_limiter = Arc::new(
        RateLimiter::new()
            .with_default_rule(RateLimitRules::general_api())
            .with_endpoint_rule("/api/auth/login".to_string(), RateLimitRules::login())
            .with_endpoint_rule("/api/auth/admin/login".to_string(), RateLimitRules::login())
            .with_endpoint_rule(
                "/api/auth/mfa/login-verify".to_string(),
                RateLimitRules::login(),
            )
            .with_endpoint_rule("/api/auth/register".to_string(), RateLimitRules::register())
            .with_endpoint_rule(
                "/api/auth/request-password-reset".to_string(),
                RateLimitRules::password_reset(),
            )
            .with_endpoint_rule(
                "/api/auth/reset-password".to_string(),
                RateLimitRules::password_reset(),
            ),
    );

    let audit_logger = Arc::new(AuditLogger::new(shared_db.clone()));
    let lockout_service = Arc::new(AccountLockoutService::new(
        shared_db.clone(),
        config.clone(),
        audit_logger.clone(),
    )?);
    let auth_cache = Arc::new(AuthCache::new(config.session_cache_ttl_seconds));
    if auth_cache.enabled() {
        info!(
            ttl_seconds = config.session_cache_ttl_seconds,
            "Authenticated-request cache enabled; cross-instance revocation lags by at most one TTL"
        );
    } else {
        info!("Authenticated-request cache disabled; every request revalidates the session");
    }
    let signing_key = Arc::new(OidcSigningKey::load(&config)?);
    let oidc_service = Arc::new(OidcService::new(
        shared_db.clone(),
        config.clone(),
        signing_key,
    )?);
    let oidc_client_service = Arc::new(OidcClientService::new(shared_db.clone()));
    let sso_session_service = Arc::new(SsoSessionService::new(shared_db.clone()));
    // AuthService 内部持有 OAuth / SMTP / MFA 客户端，构造一次复用，
    // 不再每个请求重新建一遍。
    let auth_service = Arc::new(AuthService::new(
        shared_db.clone(),
        config.clone(),
        auth_cache.clone(),
    )?);

    // 后台清理任务
    let cleanup_limiter = rate_limiter.clone();
    let cleanup_lockout = lockout_service.clone();
    let cleanup_sso = sso_session_service.clone();
    let cleanup_oidc = oidc_service.clone();
    let cleanup_auth_cache = auth_cache.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            cleanup_limiter.cleanup_expired_records().await;
            if let Err(e) = cleanup_lockout.cleanup_expired_lockouts().await {
                error!("Failed to clean up expired lockouts: {e}");
            }
            if let Err(e) = cleanup_sso.cleanup_expired_sessions().await {
                error!("Failed to clean up expired SSO sessions: {e}");
            }
            if let Err(e) = cleanup_oidc.cleanup_expired_artifacts().await {
                error!("Failed to clean up expired OIDC tokens: {e}");
            }
            cleanup_auth_cache.purge_expired().await;
        }
    });

    // SurrealDB 的 HTTP 鉴权态会因空闲而过期，定期保活。
    let keepalive_db = shared_db.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(error) = keepalive_db.verify_connection().await {
                warn!("Database keepalive failed: {}", error);
            }
        }
    });

    let app_state = Arc::new(AppState {
        db,
        config: config.clone(),
        rate_limiter: rate_limiter.clone(),
        lockout_service: lockout_service.clone(),
    });

    let app = Router::new()
        .nest("/api/auth", routes::auth::router())
        .nest("/api/rbac", routes::rbac::router())
        .nest("/api/users", routes::user_management::router())
        .nest("/api/ops", routes::ops::router())
        .nest("/api/audit", routes::audit::audit_routes())
        .nest("/api/oidc", routes::oidc::oidc_routes())
        .nest("/api/oidc", routes::oidc_client::oidc_client_routes())
        .nest("/api/sso", routes::sso_session::sso_session_routes())
        .merge(routes::oidc::discovery_routes()) // 根路径上的 /.well-known 发现端点
        // 限流放在最内层：外层的 Extension 已经注入，它才能拿到 AppState / Config。
        .layer(middleware::from_fn(rate_limit_layer))
        .layer(Extension(shared_db))
        .layer(Extension(app_state))
        .layer(Extension(auth_service))
        .layer(Extension(auth_cache))
        .layer(Extension(audit_logger))
        .layer(Extension(config.clone()))
        .layer(Extension(oidc_service))
        .layer(Extension(oidc_client_service))
        .layer(Extension(sso_session_service))
        .layer(build_cors_layer(&config));

    let addr = "0.0.0.0:8080";
    info!("Server listening on {}", addr);
    axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}
