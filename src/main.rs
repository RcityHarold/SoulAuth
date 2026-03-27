use std::{sync::Arc, net::SocketAddr};
use axum::{
    routing::Router,
    Extension,
};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing::info;
use tokio::time::{interval, Duration};

mod routes;
mod models;
mod services;
mod config;
mod error;
mod utils;

use crate::{
    config::Config,
    services::{
        database::Database, 
        rate_limiter::{RateLimiter, RateLimitRules},
        account_lockout::AccountLockoutService,
        oidc::OidcService,
        oidc_client_management::OidcClientService,
        social_hub::SocialHub,
        sso_session_management::SsoSessionService,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub rate_limiter: Arc<RateLimiter>,
    pub lockout_service: Arc<AccountLockoutService>,
    pub social_hub: Arc<SocialHub>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("rust_auth=debug,tower_http=debug"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting auth service...");

    // 检查是否处于安装模式（通过检查docs系统的安装状态）
    let docs_install_marker = "../Rainbow-docs/.rainbow_docs_installed";
    if !std::path::Path::new(docs_install_marker).exists() {
        info!("System appears to be in installation mode. Auth service will wait for installation to complete...");
        
        // 等待安装完成
        loop {
            if std::path::Path::new(docs_install_marker).exists() {
                info!("Installation completed. Starting auth service...");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        
        // 安装完成后等待一下，让数据库稳定
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }

    // 加载配置
    dotenv::dotenv().ok();
    let config = Config::from_env()?;

    // 初始化数据库连接
    let db = Database::new(&config).await?;
    db.verify_connection().await?;
    
    info!("Database connection established. Please ensure database schema is initialized with schema.sql and initial_data.sql");

    // 创建共享的数据库实例
    let shared_db = Arc::new(db.clone());

    // 创建速率限制器
    let rate_limiter = Arc::new(
        RateLimiter::new()
            .with_default_rule(RateLimitRules::general_api())
            .with_endpoint_rule("/api/auth/login".to_string(), RateLimitRules::login())
            .with_endpoint_rule("/api/auth/register".to_string(), RateLimitRules::register())
            .with_endpoint_rule("/api/auth/forgot-password".to_string(), RateLimitRules::password_reset())
            .with_endpoint_rule("/api/auth/verify-email".to_string(), RateLimitRules::email_verification())
    );

    // 创建账户锁定服务
    let lockout_service = Arc::new(AccountLockoutService::new(shared_db.clone(), config.clone())?);

    // 创建 OIDC 服务
    let oidc_service = Arc::new(OidcService::new(shared_db.clone(), config.clone())?);
    let oidc_client_service = Arc::new(OidcClientService::new(shared_db.clone()));
    let sso_session_service = Arc::new(SsoSessionService::new(shared_db.clone()));
    let social_hub = Arc::new(SocialHub::new());

    // 启动定期清理任务
    let cleanup_limiter = rate_limiter.clone();
    let cleanup_lockout = lockout_service.clone();
    let cleanup_sso = sso_session_service.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(3600)); // 每小时清理一次
        loop {
            interval.tick().await;
            cleanup_limiter.cleanup_expired_records().await;
            let _ = cleanup_lockout.cleanup_expired_lockouts().await;
            let _ = cleanup_sso.cleanup_expired_sessions().await;
        }
    });

    // 创建 app state
    let app_state = AppState {
        db,
        config: config.clone(),
        rate_limiter: rate_limiter.clone(),
        lockout_service: lockout_service.clone(),
        social_hub: social_hub.clone(),
    };

    // 创建路由
    let app = Router::new()
        .nest("/api/auth", routes::auth::router(shared_db.clone()))
        .nest("/api/rbac", routes::rbac::router())
        .nest("/api/users", routes::user_management::router())
        .nest("/api/audit", routes::audit::audit_routes())
        .nest("/api/oidc", routes::oidc::oidc_routes())
        .nest("/api/oidc", routes::oidc_client::oidc_client_routes())
        .nest("/api/sso", routes::sso_session::sso_session_routes())
        .nest("", routes::oidc::oidc_routes()) // 为 /.well-known 路径
        .layer(Extension(shared_db))
        .layer(Extension(Arc::new(app_state)))
        .layer(Extension(social_hub))
        .layer(Extension(config.clone()))  // 添加 Config 扩展
        .layer(Extension(oidc_service))     // 添加 OIDC 服务扩展
        .layer(Extension(oidc_client_service)) // 添加 OIDC 客户端服务扩展
        .layer(Extension(sso_session_service)) // 添加 SSO 会话服务扩展
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // 启动服务器
    let addr = "0.0.0.0:8080";
    info!("Server listening on {}", addr);
    axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}
