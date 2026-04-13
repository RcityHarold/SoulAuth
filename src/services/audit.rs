use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{error, info, warn};

use crate::{
    error::{Result as ApiResult, AuthError},
    services::database::Database,
    routes::audit::{
        ActivityMetric, AuthenticationStats, CategoryMetric, ExecutiveSummary,
        FrequencyMetric, GeographicMetric, HourlyActivity, IpActivityMetric,
        LockoutStats, RetentionMetrics, SecurityIncident, SecurityRecommendation,
        StatusMetric, SuspiciousActivity, TimeseriesData, UserActivityMetric,
        UserBehaviorAnalysis,
    },
};

#[derive(Clone)]
pub struct AuditService {
    db: Database,
}

impl AuditService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    // Authentication Statistics
    pub async fn get_authentication_stats(
        &self,
        start_time: DateTime<Utc>,
    ) -> ApiResult<AuthenticationStats> {
        let successful_query = "SELECT count() as count FROM user_activity WHERE action IN ['login_success', 'oauth_login'] AND timestamp >= $start_time GROUP ALL";
        let failed_query = "SELECT count() as count FROM user_activity WHERE action = 'login_failed' AND timestamp >= $start_time GROUP ALL";
        let oauth_query = "SELECT count() as count FROM user_activity WHERE action = 'oauth_login' AND timestamp >= $start_time GROUP ALL";
        let reset_query = "SELECT count() as count FROM user_activity WHERE action = 'password_reset' AND timestamp >= $start_time GROUP ALL";

        let successful_logins = self.execute_count_query(successful_query, start_time).await?;
        let failed_logins = self.execute_count_query(failed_query, start_time).await?;
        let oauth_logins = self.execute_count_query(oauth_query, start_time).await?;
        let password_resets = self.execute_count_query(reset_query, start_time).await?;

        let total_attempts = successful_logins + failed_logins;
        let success_rate = if total_attempts > 0 {
            (successful_logins as f64 / total_attempts as f64) * 100.0
        } else {
            0.0
        };

        Ok(AuthenticationStats {
            successful_logins,
            failed_logins,
            oauth_logins,
            password_resets,
            success_rate,
        })
    }

    // Lockout Statistics
    pub async fn get_lockout_stats(&self, start_time: DateTime<Utc>) -> ApiResult<LockoutStats> {
        let user_lockouts_query = "SELECT count() as count FROM account_lockout WHERE lockout_type = 'User' AND locked_at >= $start_time GROUP ALL";
        let ip_lockouts_query = "SELECT count() as count FROM account_lockout WHERE lockout_type = 'IpAddress' AND locked_at >= $start_time GROUP ALL";
        let active_lockouts_query = "SELECT count() as count FROM account_lockout WHERE status = 'Locked' AND locked_until > $now GROUP ALL";

        let user_lockouts = self.execute_count_query(user_lockouts_query, start_time).await?;
        let ip_lockouts = self.execute_count_query(ip_lockouts_query, start_time).await?;
        
        let mut active_result = self.db.client.query(active_lockouts_query)
            .bind(("now", Utc::now()))
            .await
            .map_err(|e| {
                error!("Failed to get active lockouts count: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;
        
        let active_lockouts: Option<i64> = active_result.take("count").map_err(|e| {
            error!("Failed to extract active lockouts count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;

        // Calculate average lockout duration
        let duration_query = "SELECT locked_at, locked_until FROM account_lockout WHERE locked_at >= $start_time AND locked_until IS NOT NULL";
        let mut duration_result = self.db.client.query(duration_query)
            .bind(("start_time", start_time))
            .await
            .map_err(|e| {
                error!("Failed to get lockout durations: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let durations: Vec<(DateTime<Utc>, DateTime<Utc>)> = duration_result.take(0).unwrap_or_default();
        let average_lockout_duration_minutes = if !durations.is_empty() {
            let total_minutes: i64 = durations.iter()
                .map(|(start, end)| (*end - *start).num_minutes())
                .sum();
            total_minutes as f64 / durations.len() as f64
        } else {
            0.0
        };

        Ok(LockoutStats {
            user_lockouts,
            ip_lockouts,
            active_lockouts: active_lockouts.unwrap_or(0),
            average_lockout_duration_minutes,
        })
    }

    // Rate Limit Violations (estimated from failed login attempts with high frequency)
    pub async fn get_rate_limit_violations(&self, start_time: DateTime<Utc>) -> ApiResult<i64> {
        // Since we don't store rate limit violations directly, we estimate from pattern analysis
        let query = "SELECT ip_address, count() as count FROM user_activity WHERE action = 'login_failed' AND timestamp >= $start_time GROUP BY ip_address";
        let mut result = self.db.client.query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .map_err(|e| {
                error!("Failed to get rate limit violations: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let violations: Vec<(String, i64)> = result.take(0).unwrap_or_default();
        Ok(violations.into_iter().filter(|(_, count)| *count > 10).count() as i64)
    }

    // Permission Denials
    pub async fn get_permission_denials(&self, start_time: DateTime<Utc>) -> ApiResult<i64> {
        let query = "SELECT count() as count FROM user_activity WHERE action = 'permission_denied' AND timestamp >= $start_time GROUP ALL";
        self.execute_count_query(query, start_time).await
    }

    // Failed Login by IP
    pub async fn get_failed_login_by_ip(&self, start_time: DateTime<Utc>) -> ApiResult<Vec<IpActivityMetric>> {
        let query = "SELECT ip_address, count() as failed_attempts, math::max(timestamp) as last_attempt FROM user_activity WHERE action = 'login_failed' AND timestamp >= $start_time GROUP BY ip_address ORDER BY failed_attempts DESC LIMIT 20";
        
        let mut result = self.db.client.query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .map_err(|e| {
                error!("Failed to get failed login by IP: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let ip_data: Vec<(String, i64, i64)> = result.take(0).unwrap_or_default();
        
        let mut metrics = Vec::new();
        for (ip_address, failed_attempts, last_attempt_timestamp) in ip_data {
            // Check if IP is currently locked
            let lockout_query = "SELECT status FROM account_lockout WHERE identifier = $ip AND lockout_type = 'IpAddress' AND locked_until > $now";
            let mut lockout_result = self.db.client.query(lockout_query)
                .bind(("ip", ip_address.clone()))
                .bind(("now", Utc::now().to_string()))
                .await
                .map_err(|e| {
                    error!("Failed to check IP lockout status: {}", e);
                    AuthError::DatabaseError("Query execution failed".to_string())
                })?;

            let is_locked: Option<String> = lockout_result.take("status").unwrap_or(None);
            let last_attempt = DateTime::from_timestamp(last_attempt_timestamp, 0)
                .unwrap_or_else(|| Utc::now());

            metrics.push(IpActivityMetric {
                ip_address,
                failed_attempts,
                is_locked: is_locked.is_some(),
                last_attempt,
            });
        }

        Ok(metrics)
    }

    // Suspicious Activities Detection
    pub async fn get_suspicious_activities(&self, start_time: DateTime<Utc>) -> ApiResult<Vec<SuspiciousActivity>> {
        // Multiple criteria for suspicious activity:
        // 1. High frequency failed logins from same IP
        // 2. Login attempts from unusual locations
        // 3. Multiple account access attempts
        
        let query = "SELECT ip_address, user_id, action, count() as count, math::min(timestamp) as first_seen, math::max(timestamp) as last_seen FROM user_activity WHERE timestamp >= $start_time AND (action = 'login_failed' OR action = 'permission_denied') GROUP BY ip_address, user_id, action ORDER BY count DESC LIMIT 50";
        
        let mut result = self.db.client.query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .map_err(|e| {
                error!("Failed to get suspicious activities: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let activities: Vec<(String, Option<String>, String, i64, i64, i64)> = result.take(0).unwrap_or_default();
        
        let mut suspicious = Vec::new();
        for (ip_address, user_id, activity_type, count, first_seen_ts, last_seen_ts) in activities {
            if count <= 5 {
                continue;
            }
            let risk_score = self.calculate_risk_score(count, &activity_type);
            let first_seen = DateTime::from_timestamp(first_seen_ts, 0).unwrap_or_else(|| Utc::now());
            let last_seen = DateTime::from_timestamp(last_seen_ts, 0).unwrap_or_else(|| Utc::now());

            suspicious.push(SuspiciousActivity {
                user_id,
                ip_address,
                activity_type,
                count,
                risk_score,
                first_seen,
                last_seen,
            });
        }

        Ok(suspicious)
    }

    // Activities by Category
    pub async fn get_activities_by_category(&self, start_time: DateTime<Utc>) -> ApiResult<Vec<CategoryMetric>> {
        let query = "SELECT category, count() as count FROM user_activity WHERE timestamp >= $start_time GROUP BY category ORDER BY count DESC";
        let mut result = self.db.client.query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .map_err(|e| {
                error!("Failed to get activities by category: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let categories: Vec<(String, i64)> = result.take(0).unwrap_or_default();
        let total: i64 = categories.iter().map(|(_, count)| count).sum();

        Ok(categories.into_iter().map(|(category, count)| {
            CategoryMetric {
                category,
                count,
                percentage: if total > 0 { (count as f64 / total as f64) * 100.0 } else { 0.0 },
            }
        }).collect())
    }

    // Activities by Status
    pub async fn get_activities_by_status(&self, start_time: DateTime<Utc>) -> ApiResult<Vec<StatusMetric>> {
        let query = "SELECT status, count() as count FROM user_activity WHERE timestamp >= $start_time GROUP BY status ORDER BY count DESC";
        let mut result = self.db.client.query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .map_err(|e| {
                error!("Failed to get activities by status: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let statuses: Vec<(String, i64)> = result.take(0).unwrap_or_default();
        let total: i64 = statuses.iter().map(|(_, count)| count).sum();

        Ok(statuses.into_iter().map(|(status, count)| {
            StatusMetric {
                status,
                count,
                percentage: if total > 0 { (count as f64 / total as f64) * 100.0 } else { 0.0 },
            }
        }).collect())
    }

    // Top Active Users
    pub async fn get_top_active_users(&self, start_time: DateTime<Utc>) -> ApiResult<Vec<UserActivityMetric>> {
        // SurrealDB 3.x: avoid JOIN; aggregate first, then resolve user email map.
        let query = "SELECT type::string(user_id) as user_id, count() as activity_count, math::max(timestamp) as last_activity FROM user_activity WHERE timestamp >= $start_time AND user_id IS NOT NULL GROUP BY user_id ORDER BY activity_count DESC LIMIT 20";

        let mut result = self.db.client.query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .map_err(|e| {
                error!("Failed to get top active users: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let rows: Vec<Value> = result.take(0).unwrap_or_default();

        let mut compact_rows: Vec<(String, i64, i64)> = Vec::new();
        let mut user_keys: Vec<String> = Vec::new();
        for row in rows {
            let obj = match row {
                Value::Object(o) => o,
                _ => continue,
            };

            let user_id = obj.get("user_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if user_id.is_empty() {
                continue;
            }

            let activity_count = obj.get("activity_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            let last_activity_ts = obj.get("last_activity")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);

            // Normalize to `user:<uuid>` for lookup in user table.
            let normalized = user_id
                .trim_start_matches("user:")
                .trim_matches(|c| c == '⟨' || c == '⟩');
            user_keys.push(format!("user:{}", normalized));
            compact_rows.push((user_id, activity_count, last_activity_ts));
        }

        let mut email_map: HashMap<String, String> = HashMap::new();
        if !user_keys.is_empty() {
            let user_query = "SELECT type::string(id) as id, email FROM user WHERE type::string(id) IN $user_ids";
            let mut user_result = self.db.client.query(user_query)
                .bind(("user_ids", user_keys))
                .await
                .map_err(|e| {
                    error!("Failed to query user emails: {}", e);
                    AuthError::DatabaseError("Query execution failed".to_string())
                })?;

            let user_rows: Vec<Value> = user_result.take(0).unwrap_or_default();
            for row in user_rows {
                let obj = match row {
                    Value::Object(o) => o,
                    _ => continue,
                };
                let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let email = obj.get("email").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !id.is_empty() {
                    email_map.insert(id, email);
                }
            }
        }

        let users = compact_rows.into_iter().map(|(user_id, activity_count, last_activity_ts)| {
            let normalized = user_id
                .trim_start_matches("user:")
                .trim_matches(|c| c == '⟨' || c == '⟩');
            let lookup_id = format!("user:{}", normalized);
            let email = email_map.get(&lookup_id).cloned().unwrap_or_default();
            let last_activity = DateTime::from_timestamp(last_activity_ts, 0).unwrap_or_else(Utc::now);

            UserActivityMetric {
                user_id,
                email,
                activity_count,
                last_activity,
            }
        }).collect();

        Ok(users)
    }

    // Hourly Activity Distribution
    pub async fn get_hourly_activity_distribution(&self, start_time: DateTime<Utc>) -> ApiResult<Vec<HourlyActivity>> {
        let query = "SELECT time::hour(timestamp) as hour, count() as count FROM user_activity WHERE timestamp >= $start_time GROUP BY hour ORDER BY hour";
        
        let mut result = self.db.client.query(query)
            .bind(("start_time", start_time.timestamp()))
            .await
            .map_err(|e| {
                error!("Failed to get hourly activity distribution: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        let hourly_data: Vec<(i32, i64)> = result.take(0).unwrap_or_default();
        
        // Fill in missing hours with 0 count
        let mut hourly_map: HashMap<i32, i64> = hourly_data.into_iter().collect();
        let mut distribution = Vec::new();
        
        for hour in 0..24 {
            distribution.push(HourlyActivity {
                hour,
                count: *hourly_map.get(&hour).unwrap_or(&0),
            });
        }

        Ok(distribution)
    }

    // Generate Executive Summary
    pub async fn generate_executive_summary(&self, start_time: DateTime<Utc>) -> ApiResult<ExecutiveSummary> {
        let total_users = self.get_total_users().await?;
        let active_users = self.get_active_users_count(start_time).await?;
        let security_incidents = self.get_security_incidents_count(start_time).await?;
        let auth_stats = self.get_authentication_stats(start_time).await?;
        
        let risk_level = self.calculate_risk_level(security_incidents, auth_stats.success_rate).await;

        Ok(ExecutiveSummary {
            total_users,
            active_users,
            security_incidents,
            success_rate: auth_stats.success_rate,
            risk_level,
        })
    }

    // Security Recommendations
    pub async fn generate_security_recommendations(&self, start_time: DateTime<Utc>) -> ApiResult<Vec<SecurityRecommendation>> {
        let mut recommendations = Vec::new();
        
        // Check authentication success rate
        let auth_stats = self.get_authentication_stats(start_time).await?;
        if auth_stats.success_rate < 90.0 {
            recommendations.push(SecurityRecommendation {
                priority: "High".to_string(),
                category: "Authentication".to_string(),
                title: "Low Authentication Success Rate".to_string(),
                description: format!(
                    "Authentication success rate is {:.1}%, which is below the recommended 90%. Consider investigating failed login patterns and implementing additional security measures.",
                    auth_stats.success_rate
                ),
                estimated_impact: "High".to_string(),
            });
        }

        // Check for suspicious activities
        let suspicious = self.get_suspicious_activities(start_time).await?;
        if !suspicious.is_empty() {
            let high_risk_count = suspicious.iter().filter(|s| s.risk_score > 7).count();
            if high_risk_count > 0 {
                recommendations.push(SecurityRecommendation {
                    priority: "High".to_string(),
                    category: "Security".to_string(),
                    title: "High-Risk Suspicious Activities Detected".to_string(),
                    description: format!(
                        "Detected {} high-risk suspicious activities. Review and investigate these activities immediately.",
                        high_risk_count
                    ),
                    estimated_impact: "Critical".to_string(),
                });
            }
        }

        // Check lockout patterns
        let lockout_stats = self.get_lockout_stats(start_time).await?;
        if lockout_stats.user_lockouts > 10 {
            recommendations.push(SecurityRecommendation {
                priority: "Medium".to_string(),
                category: "Security".to_string(),
                title: "High Number of Account Lockouts".to_string(),
                description: format!(
                    "There have been {} user account lockouts in the analysis period. Consider reviewing password policies and user education.",
                    lockout_stats.user_lockouts
                ),
                estimated_impact: "Medium".to_string(),
            });
        }

        // Default recommendation if no issues found
        if recommendations.is_empty() {
            recommendations.push(SecurityRecommendation {
                priority: "Low".to_string(),
                category: "General".to_string(),
                title: "Security Status Normal".to_string(),
                description: "No critical security issues detected in the analysis period. Continue monitoring and maintain current security practices.".to_string(),
                estimated_impact: "Low".to_string(),
            });
        }

        Ok(recommendations)
    }

    // Helper methods
    async fn execute_count_query(&self, query: &str, start_time: DateTime<Utc>) -> ApiResult<i64> {
        let count_result: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "audit_execute_count_query",
                query,
                json!({ "start_time": start_time.timestamp() }),
            )
            .await
            .map_err(|e| {
                error!("Failed to execute count query: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        Ok(count_result
            .first()
            .and_then(|c| c.get("count"))
            .and_then(|c| c.as_i64())
            .unwrap_or(0))
    }

    async fn get_total_users(&self) -> ApiResult<i64> {
        let query = "SELECT count() as count FROM user WHERE account_status != 'Deleted' GROUP ALL";
        let count_result: Vec<serde_json::Value> = self
            .db
            .query_take0_vec_no_bind("audit_get_total_users", query)
            .await
            .map_err(|e| {
                error!("Failed to get total users: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;

        Ok(count_result
            .first()
            .and_then(|c| c.get("count"))
            .and_then(|c| c.as_i64())
            .unwrap_or(0))
    }

    async fn get_active_users_count(&self, start_time: DateTime<Utc>) -> ApiResult<i64> {
        let query = "SELECT type::string(user_id) as user_id FROM user_activity WHERE timestamp >= $start_time AND user_id IS NOT NULL GROUP BY user_id";
        let rows: Vec<Value> = self
            .db
            .query_take0_vec(
                "audit_get_active_users_count",
                query,
                json!({ "start_time": start_time.timestamp() }),
            )
            .await
            .map_err(|e| {
                error!("Failed to get active users count: {}", e);
                AuthError::DatabaseError("Query execution failed".to_string())
            })?;
        Ok(rows.len() as i64)
    }

    async fn get_security_incidents_count(&self, start_time: DateTime<Utc>) -> ApiResult<i64> {
        let query = "SELECT count() as count FROM user_activity WHERE category = 'Security' AND status IN ['Failed', 'Warning'] AND timestamp >= $start_time GROUP ALL";
        self.execute_count_query(query, start_time).await
    }

    fn calculate_risk_score(&self, count: i64, activity_type: &str) -> i32 {
        let base_score = match activity_type {
            "login_failed" => 2,
            "permission_denied" => 3,
            "account_locked" => 5,
            _ => 1,
        };

        let frequency_multiplier = match count {
            0..=5 => 1,
            6..=10 => 2,
            11..=20 => 3,
            _ => 4,
        };

        (base_score * frequency_multiplier).min(10)
    }

    async fn calculate_risk_level(&self, security_incidents: i64, success_rate: f64) -> String {
        if security_incidents > 20 || success_rate < 80.0 {
            "High".to_string()
        } else if security_incidents > 10 || success_rate < 90.0 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        }
    }
}
