use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

use crate::{
    config::Config,
    models::user_activity::{ActivityCategory, ActivityStatus},
    services::audit_logger::{actions, AuditEvent, AuditLogger},
    AppState,
};

/// 解析客户端 IP。
///
/// `trust_proxy_headers` 为 false（默认）时**只**采用 TCP 连接地址：否则任何客户端
/// 都能通过伪造 `X-Forwarded-For` 绕开限流和 IP 维度的账号锁定。只有当服务确实
/// 部署在受控反向代理之后时才应打开该开关。
pub fn client_ip(addr: &SocketAddr, headers: &HeaderMap, trust_proxy_headers: bool) -> String {
    if trust_proxy_headers {
        if let Some(forwarded_for) = headers.get("X-Forwarded-For") {
            if let Ok(forwarded_str) = forwarded_for.to_str() {
                if let Some(ip) = forwarded_str.split(',').next() {
                    let ip = ip.trim();
                    if !ip.is_empty() {
                        return ip.to_string();
                    }
                }
            }
        }

        if let Some(real_ip) = headers.get("X-Real-IP") {
            if let Ok(ip_str) = real_ip.to_str() {
                let ip_str = ip_str.trim();
                if !ip_str.is_empty() {
                    return ip_str.to_string();
                }
            }
        }
    }

    addr.ip().to_string()
}

/// 全局限流中间件。
///
/// 以前限流只在少数几个 handler 里手动调用，其余端点完全没有保护；现在统一挂在
/// 路由外层，按请求路径套用对应规则。
///
/// 注意：计数器保存在单进程内存里，多副本部署时每个副本各算各的。需要跨副本
/// 限流请把 `RateLimiter` 换成共享存储实现。
pub async fn rate_limit_layer<B>(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(audit): Extension<Arc<AuditLogger>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    req: Request<B>,
    next: Next<B>,
) -> Response {
    let ip = client_ip(&addr, &headers, config.trust_proxy_headers);
    let endpoint = req.uri().path().to_string();

    match app_state.rate_limiter.check_rate_limit(&ip, &endpoint).await {
        Ok(true) => next.run(req).await,
        Ok(false) => {
            let user_agent = headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("Unknown")
                .chars()
                .take(256)
                .collect::<String>();

            audit.record(
                AuditEvent::new(
                    actions::RATE_LIMIT_VIOLATION,
                    ActivityCategory::Security,
                    ActivityStatus::Warning,
                    ip.clone(),
                    user_agent,
                )
                .with_details(serde_json::json!({ "endpoint": endpoint })),
            );

            rate_limited_response(&ip, &endpoint)
        }
        Err(e) => {
            // 限流器自身故障不应导致全站不可用。
            warn!("Rate limiter error on {}: {}", endpoint, e);
            next.run(req).await
        }
    }
}

fn rate_limited_response(ip: &str, endpoint: &str) -> Response {
    warn!("Rate limit exceeded for client: {}, endpoint: {}", ip, endpoint);
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please try again later.",
            "code": "RATE_LIMIT_EXCEEDED"
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 8080)
    }

    #[test]
    fn ignores_forwarded_headers_when_proxy_is_not_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "192.168.1.1, 10.0.0.1".parse().unwrap());
        headers.insert("X-Real-IP", "192.168.1.100".parse().unwrap());

        assert_eq!(client_ip(&addr(), &headers, false), "203.0.113.7");
    }

    #[test]
    fn uses_first_forwarded_hop_when_proxy_is_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "192.168.1.1, 10.0.0.1".parse().unwrap());

        assert_eq!(client_ip(&addr(), &headers, true), "192.168.1.1");
    }

    #[test]
    fn falls_back_to_real_ip_then_socket_addr() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "192.168.1.100".parse().unwrap());
        assert_eq!(client_ip(&addr(), &headers, true), "192.168.1.100");

        let empty = HeaderMap::new();
        assert_eq!(client_ip(&addr(), &empty, true), "203.0.113.7");
    }
}
