use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Instant,
};

use axum::{http::HeaderValue, middleware, routing::{get, Router}, Extension, Json};
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

/// 存活探针。
///
/// DEPLOYMENT.md 从第一版起就让运维 `curl /health` 验证部署，而这个端点
/// **从来没有存在过** —— 返回 404。它同时也是容器编排的 liveness probe 目标，
/// 成本近乎为零，所以补上而不是把文档改掉。
///
/// 只报告进程存活，不查数据库：liveness 探针失败会触发重启，而数据库抖动
/// 重启应用救不了，反而会在故障时把所有副本一起打掉。数据库连通性属于
/// readiness 语义，已由 `/api/audit/system-health` 提供（需鉴权）。
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "uptime_seconds": process_uptime_seconds(),
    }))
}

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub rate_limiter: Arc<RateLimiter>,
    pub lockout_service: Arc<AccountLockoutService>,
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
            std::env::var("RUST_LOG").unwrap_or_else(|_| "soulauth=debug,tower_http=info".to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let _ = PROCESS_START.set(Instant::now());
    info!("Starting auth service...");

    dotenvy::dotenv().ok();
    let config = Config::from_env()?;

    // 数据库 schema 由 schema.sql / initial_data.sql 负责，应用本身不做 DDL。
    let db = Database::new(&config).await?;
    db.verify_connection().await?;
    // 连得上不等于能用：空库同样通过 `INFO FOR DB`。这一步确认 schema 与种子数据
    // 确实在本进程连接的那个 ns/db 上，否则带着 ns/db 一起拒绝启动。
    db.ensure_schema_initialised().await?;
    info!(
        namespace = %config.database_namespace,
        database = %config.database_name,
        "Database connection established and schema verified"
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
            )
            // 下面两个是“拿着令牌猜”的端点，键必须写成路由模板才对得上
            // `MatchedPath`。以前它们连默认规则都形同虚设（每个 token 一个桶）。
            .with_endpoint_rule(
                "/api/auth/verify-email/:token".to_string(),
                RateLimitRules::password_reset(),
            )
            .with_endpoint_rule(
                "/api/auth/initialize-password".to_string(),
                RateLimitRules::password_reset(),
            )
            // 重发验证信：既是发信端点也是"该邮箱注册了没有"的潜在探针，
            // 与密码重置同档限流。
            .with_endpoint_rule(
                "/api/auth/resend-verification".to_string(),
                RateLimitRules::password_reset(),
            )
            // 上面这些端点的计数走共享后端，跨副本合账。不接的话，部署 N 个
            // 副本就等于把暴力破解配额放大 N 倍 —— 每个副本各算各的。
            // 一般 API（默认规则）仍走进程内，不给每个请求加一次数据库往返。
            .with_shared_backend(shared_db.clone()),
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
    let cleanup_oidc = oidc_service.clone();
    let cleanup_auth_cache = auth_cache.clone();
    let cleanup_db = shared_db.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            cleanup_limiter.cleanup_expired_records().await;
            if let Err(e) = cleanup_lockout.cleanup_expired_lockouts().await {
                error!("Failed to clean up expired lockouts: {e}");
            }
            if let Err(e) = cleanup_oidc.cleanup_expired_artifacts().await {
                error!("Failed to clean up expired OIDC tokens: {e}");
            }
            // 过期会话与失效的重置令牌。这两张表以前不在清理范围内，只增不减。
            if let Err(e) = cleanup_db.cleanup_expired_auth_artifacts().await {
                error!("Failed to clean up expired sessions / reset tokens: {e}");
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
        .merge(routes::oidc::discovery_routes()) // 根路径上的 /.well-known 发现端点
        // 限流放在最内层：外层的 Extension 已经注入，它才能拿到 AppState / Config。
        //
        // 用 `route_layer` 而不是 `layer`：前者在路由匹配之后执行，中间件才能读到
        // `MatchedPath`（`/api/auth/verify-email/:token` 这样的模板）。挂在 `layer`
        // 上只能拿到原始路径，带参数的端点会一个 token 一个计数桶，等于不限流。
        // 代价是打不中任何路由的请求（404）不再计数，这类请求本来也不碰业务逻辑。
        .route_layer(middleware::from_fn(rate_limit_layer))
        // `/health` 挂在限流层**之后**注册，因此不受限流约束。
        // 编排器的 liveness 探针如果被 429 打回，会被判成"进程死了"进而重启副本 ——
        // 限流本是为了抗压，那样反而成了压力下的自杀开关。
        .route("/health", get(health))
        .layer(Extension(shared_db))
        .layer(Extension(app_state))
        .layer(Extension(auth_service))
        .layer(Extension(auth_cache))
        .layer(Extension(audit_logger))
        .layer(Extension(config.clone()))
        .layer(Extension(oidc_service))
        .layer(Extension(oidc_client_service))
        .layer(build_cors_layer(&config));

    let addr: SocketAddr = config.bind_addr.parse().map_err(|e| {
        anyhow::anyhow!("Invalid BIND_ADDR `{}`: {e}", config.bind_addr)
    })?;
    info!("Server listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}
