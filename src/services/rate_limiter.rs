use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// 速率限制规则
#[derive(Debug, Clone)]
pub struct RateLimitRule {
    /// 时间窗口大小
    pub window_duration: Duration,
    /// 时间窗口内最大请求数
    pub max_requests: u32,
    /// 阻塞时长
    pub block_duration: Duration,
}

impl Default for RateLimitRule {
    fn default() -> Self {
        Self {
            window_duration: Duration::from_secs(60),  // 1分钟窗口
            max_requests: 10,                          // 最多10次请求
            block_duration: Duration::from_secs(300), // 阻塞5分钟
        }
    }
}

/// 请求记录
#[derive(Debug, Clone)]
struct RequestRecord {
    /// 请求时间戳列表
    timestamps: Vec<Instant>,
    /// 阻塞开始时间
    blocked_until: Option<Instant>,
}

impl RequestRecord {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            blocked_until: None,
        }
    }

    /// 检查是否被阻塞
    fn is_blocked(&self) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            Instant::now() < blocked_until
        } else {
            false
        }
    }

    /// 清理过期的时间戳
    fn cleanup_expired(&mut self, window_duration: Duration) {
        let cutoff = Instant::now() - window_duration;
        self.timestamps.retain(|&timestamp| timestamp > cutoff);
    }

    /// 添加请求时间戳
    fn add_request(&mut self) {
        self.timestamps.push(Instant::now());
    }

    /// 设置阻塞
    fn block(&mut self, block_duration: Duration) {
        self.blocked_until = Some(Instant::now() + block_duration);
    }

    /// 检查请求数是否超限
    fn is_rate_limited(&self, max_requests: u32) -> bool {
        self.timestamps.len() >= max_requests as usize
    }
}

/// 速率限制器
pub struct RateLimiter {
    /// 默认规则
    default_rule: RateLimitRule,
    /// 特定端点的规则
    endpoint_rules: HashMap<String, RateLimitRule>,
    /// 请求记录存储
    records: Arc<RwLock<HashMap<String, RequestRecord>>>,
}

impl RateLimiter {
    /// 创建新的速率限制器
    pub fn new() -> Self {
        Self {
            default_rule: RateLimitRule::default(),
            endpoint_rules: HashMap::new(),
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 设置默认规则
    pub fn with_default_rule(mut self, rule: RateLimitRule) -> Self {
        self.default_rule = rule;
        self
    }

    /// 为特定端点设置规则
    pub fn with_endpoint_rule(mut self, endpoint: String, rule: RateLimitRule) -> Self {
        self.endpoint_rules.insert(endpoint, rule);
        self
    }

    /// 获取端点的规则
    fn get_rule(&self, endpoint: &str) -> &RateLimitRule {
        self.endpoint_rules.get(endpoint).unwrap_or(&self.default_rule)
    }

    /// 计数桶的键：**必须**按 (客户端, 端点) 组合。
    ///
    /// 以前只用客户端 IP 做键：规则按端点挑，计数桶却是全局共用的。后果是
    /// 所有端点共享同一个配额，而生效的上限取决于你恰好打到哪个端点；
    /// 任何一个端点触发阻塞，该 IP 的**全部**端点一起被封。
    fn record_key(client_key: &str, endpoint: &str) -> String {
        format!("{client_key}\u{1}{endpoint}")
    }

    /// 检查速率限制
    pub async fn check_rate_limit(&self, key: &str, endpoint: &str) -> Result<bool, crate::error::AppError> {
        let rule = self.get_rule(endpoint);
        let mut records = self.records.write().await;

        // 获取或创建记录
        let record = records
            .entry(Self::record_key(key, endpoint))
            .or_insert_with(RequestRecord::new);

        // 检查是否被阻塞
        if record.is_blocked() {
            warn!("Rate limit blocked for key: {}, endpoint: {}", key, endpoint);
            return Ok(false);
        }

        // 清理过期记录
        record.cleanup_expired(rule.window_duration);

        // 检查是否超过限制
        if record.is_rate_limited(rule.max_requests) {
            // 触发阻塞
            record.block(rule.block_duration);
            warn!("Rate limit exceeded for key: {}, endpoint: {}, blocking for {:?}", 
                  key, endpoint, rule.block_duration);
            return Ok(false);
        }

        // 记录请求
        record.add_request();
        // 每个请求都会走到这里，放 info 会把日志淹掉（也拖慢高 QPS 下的写入）。
        debug!("Rate limit check passed for key: {}, endpoint: {}, requests: {}/{}",
              key, endpoint, record.timestamps.len(), rule.max_requests);

        Ok(true)
    }

    /// 重置某个客户端在所有端点上的限制
    pub async fn reset_limit(&self, key: &str) {
        let prefix = format!("{key}\u{1}");
        let mut records = self.records.write().await;
        records.retain(|record_key, _| !record_key.starts_with(&prefix));
        info!("Rate limit reset for key: {}", key);
    }

    /// 获取剩余请求数
    pub async fn get_remaining_requests(&self, key: &str, endpoint: &str) -> u32 {
        let rule = self.get_rule(endpoint);
        let records = self.records.read().await;
        
        if let Some(record) = records.get(&Self::record_key(key, endpoint)) {
            if record.is_blocked() {
                return 0;
            }
            rule.max_requests.saturating_sub(record.timestamps.len() as u32)
        } else {
            rule.max_requests
        }
    }

    /// 清理过期记录 (定期清理任务)
    pub async fn cleanup_expired_records(&self) {
        let mut records = self.records.write().await;
        let now = Instant::now();
        
        // 清理超过1小时没有活动的记录
        let cleanup_threshold = Duration::from_secs(3600);
        
        records.retain(|_, record| {
            // 如果有阻塞且未过期，保留
            if let Some(blocked_until) = record.blocked_until {
                if now < blocked_until {
                    return true;
                }
            }
            
            // 如果有最近的请求，保留
            if let Some(&last_request) = record.timestamps.last() {
                now - last_request < cleanup_threshold
            } else {
                false
            }
        });
        
        info!("Cleaned up rate limiter records, remaining: {}", records.len());
    }
}

/// 预定义的速率限制规则。
///
/// 规则表按端点字符串精确匹配，而中间件传进来的是**路由模板**
/// （见 `utils::rate_limit_middleware::rate_limit_endpoint`）。所以带路径参数的
/// 端点要按 `/api/auth/verify-email/:token` 这样登记，写成具体路径不会命中。
pub struct RateLimitRules;

impl RateLimitRules {
    /// 登录端点规则 (严格限制)
    pub fn login() -> RateLimitRule {
        RateLimitRule {
            window_duration: Duration::from_secs(300), // 5分钟窗口
            max_requests: 5,                           // 最多5次尝试
            block_duration: Duration::from_secs(900),  // 阻塞15分钟
        }
    }

    /// 注册端点规则
    pub fn register() -> RateLimitRule {
        RateLimitRule {
            window_duration: Duration::from_secs(300), // 5分钟窗口
            max_requests: 3,                           // 最多3次注册
            block_duration: Duration::from_secs(600),  // 阻塞10分钟
        }
    }

    /// 密码重置规则
    pub fn password_reset() -> RateLimitRule {
        RateLimitRule {
            window_duration: Duration::from_secs(900), // 15分钟窗口
            max_requests: 3,                           // 最多3次重置
            block_duration: Duration::from_secs(1800), // 阻塞30分钟
        }
    }

    /// 一般API规则
    pub fn general_api() -> RateLimitRule {
        RateLimitRule {
            window_duration: Duration::from_secs(60),  // 1分钟窗口
            max_requests: 30,                          // 最多30次请求
            block_duration: Duration::from_secs(60),   // 阻塞1分钟
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new()
            .with_default_rule(RateLimitRule {
                window_duration: Duration::from_secs(60),
                max_requests: 3,
                block_duration: Duration::from_secs(120),
            });

        let key = "test_user";
        let endpoint = "test_endpoint";

        // 前3次请求应该成功
        for i in 1..=3 {
            let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
            assert!(allowed, "Request {} should be allowed", i);
        }

        // 第4次请求应该被阻塞
        let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
        assert!(!allowed, "Request 4 should be blocked");

        // 再次请求仍应被阻塞
        let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
        assert!(!allowed, "Request 5 should still be blocked");
    }

    #[tokio::test]
    async fn test_rate_limiter_reset() {
        let limiter = RateLimiter::new()
            .with_default_rule(RateLimitRule {
                window_duration: Duration::from_secs(60),
                max_requests: 2,
                block_duration: Duration::from_secs(120),
            });

        let key = "test_user";
        let endpoint = "test_endpoint";

        // 触发限制
        limiter.check_rate_limit(key, endpoint).await.unwrap();
        limiter.check_rate_limit(key, endpoint).await.unwrap();
        let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
        assert!(!allowed, "Should be blocked");

        // 重置限制
        limiter.reset_limit(key).await;

        // 重置后应该允许请求
        let allowed = limiter.check_rate_limit(key, endpoint).await.unwrap();
        assert!(allowed, "Should be allowed after reset");
    }

    #[tokio::test]
    async fn limits_are_tracked_per_endpoint_not_globally_per_client() {
        let limiter = RateLimiter::new()
            .with_default_rule(RateLimitRule {
                window_duration: Duration::from_secs(60),
                max_requests: 2,
                block_duration: Duration::from_secs(120),
            });

        // 打满 /a 的配额
        assert!(limiter.check_rate_limit("1.2.3.4", "/a").await.unwrap());
        assert!(limiter.check_rate_limit("1.2.3.4", "/a").await.unwrap());
        assert!(!limiter.check_rate_limit("1.2.3.4", "/a").await.unwrap());

        // /b 必须仍然可用 —— 以前 /a 被封会连坐 /b
        assert!(limiter.check_rate_limit("1.2.3.4", "/b").await.unwrap());

        // 另一个客户端也不受影响
        assert!(limiter.check_rate_limit("5.6.7.8", "/a").await.unwrap());
    }

    #[tokio::test]
    async fn test_remaining_requests() {
        let limiter = RateLimiter::new()
            .with_default_rule(RateLimitRule {
                window_duration: Duration::from_secs(60),
                max_requests: 5,
                block_duration: Duration::from_secs(120),
            });

        let key = "test_user";
        let endpoint = "test_endpoint";

        // 初始应有5个剩余请求
        let remaining = limiter.get_remaining_requests(key, endpoint).await;
        assert_eq!(remaining, 5);

        // 使用2个请求
        limiter.check_rate_limit(key, endpoint).await.unwrap();
        limiter.check_rate_limit(key, endpoint).await.unwrap();

        // 应剩余3个请求
        let remaining = limiter.get_remaining_requests(key, endpoint).await;
        assert_eq!(remaining, 3);
    }
}