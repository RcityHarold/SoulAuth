use axum::{
    extract::Query,
    http::StatusCode,
    response::Json,
    routing::get,
    Extension, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

use crate::{
    config::Config,
    error::{Result as ApiResult, AuthError},
    services::{auth::AuthService, audit::AuditService, database::Database},
    utils::jwt::Claims,
    require_permission,
};

pub fn audit_routes() -> Router {
    Router::new()
        .route("/dashboard", get(get_audit_dashboard))
        .route("/security-metrics", get(get_security_metrics))
        .route("/activity-summary", get(get_activity_summary))
        .route("/system-health", get(get_system_health))
        .route("/security-report", get(generate_security_report))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub days: Option<i64>,
    pub hours: Option<i64>,
}

#[derive(Serialize)]
pub struct AuditDashboard {
    pub period: String,
    pub total_users: i64,
    pub active_sessions: i64,
    pub failed_logins: i64,
    pub locked_accounts: i64,
    pub security_events: i64,
    pub top_activities: Vec<ActivityMetric>,
    pub login_trends: Vec<TimeseriesData>,
    pub security_trends: Vec<TimeseriesData>,
}

#[derive(Serialize)]
pub struct SecurityMetrics {
    pub period: String,
    pub authentication_stats: AuthenticationStats,
    pub lockout_stats: LockoutStats,
    pub rate_limit_violations: i64,
    pub permission_denials: i64,
    pub failed_login_by_ip: Vec<IpActivityMetric>,
    pub suspicious_activities: Vec<SuspiciousActivity>,
}

#[derive(Serialize)]
pub struct ActivitySummary {
    pub period: String,
    pub total_activities: i64,
    pub by_category: Vec<CategoryMetric>,
    pub by_status: Vec<StatusMetric>,
    pub top_users: Vec<UserActivityMetric>,
    pub hourly_distribution: Vec<HourlyActivity>,
}

#[derive(Serialize)]
pub struct SystemHealth {
    pub timestamp: DateTime<Utc>,
    pub database_status: DatabaseHealth,
    pub active_sessions_count: i64,
    pub pending_lockouts: i64,
    pub memory_usage: MemoryStats,
    pub uptime_seconds: i64,
}

#[derive(Serialize)]
pub struct SecurityReport {
    pub generated_at: DateTime<Utc>,
    pub period: String,
    pub executive_summary: ExecutiveSummary,
    pub authentication_analysis: AuthenticationAnalysis,
    pub security_incidents: Vec<SecurityIncident>,
    pub user_behavior_analysis: UserBehaviorAnalysis,
    pub recommendations: Vec<SecurityRecommendation>,
}

#[derive(Serialize)]
pub struct ActivityMetric {
    pub action: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct TimeseriesData {
    pub timestamp: DateTime<Utc>,
    pub value: i64,
}

#[derive(Serialize)]
pub struct AuthenticationStats {
    pub successful_logins: i64,
    pub failed_logins: i64,
    pub oauth_logins: i64,
    pub password_resets: i64,
    pub success_rate: f64,
}

#[derive(Serialize)]
pub struct LockoutStats {
    pub user_lockouts: i64,
    pub ip_lockouts: i64,
    pub active_lockouts: i64,
    pub average_lockout_duration_minutes: f64,
}

#[derive(Serialize)]
pub struct IpActivityMetric {
    pub ip_address: String,
    pub failed_attempts: i64,
    pub is_locked: bool,
    pub last_attempt: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct SuspiciousActivity {
    pub user_id: Option<String>,
    pub ip_address: String,
    pub activity_type: String,
    pub count: i64,
    pub risk_score: i32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct CategoryMetric {
    pub category: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct StatusMetric {
    pub status: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct UserActivityMetric {
    pub user_id: String,
    pub email: String,
    pub activity_count: i64,
    pub last_activity: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct HourlyActivity {
    pub hour: i32,
    pub count: i64,
}

#[derive(Serialize)]
pub struct DatabaseHealth {
    pub connected: bool,
    pub response_time_ms: i64,
    pub connection_pool_used: i32,
    pub connection_pool_size: i32,
}

#[derive(Serialize)]
pub struct MemoryStats {
    pub used_mb: f64,
    pub available_mb: f64,
    pub usage_percentage: f64,
}

#[derive(Serialize)]
pub struct ExecutiveSummary {
    pub total_users: i64,
    pub active_users: i64,
    pub security_incidents: i64,
    pub success_rate: f64,
    pub risk_level: String,
}

#[derive(Serialize)]
pub struct AuthenticationAnalysis {
    pub login_patterns: Vec<LoginPattern>,
    pub failure_analysis: Vec<FailureAnalysis>,
    pub geographic_distribution: Vec<GeographicMetric>,
}

#[derive(Serialize)]
pub struct SecurityIncident {
    pub id: String,
    pub incident_type: String,
    pub severity: String,
    pub affected_user: Option<String>,
    pub ip_address: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub resolved: bool,
}

#[derive(Serialize)]
pub struct UserBehaviorAnalysis {
    pub login_frequency_distribution: Vec<FrequencyMetric>,
    pub peak_activity_hours: Vec<i32>,
    pub user_retention_metrics: RetentionMetrics,
}

#[derive(Serialize)]
pub struct SecurityRecommendation {
    pub priority: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub estimated_impact: String,
}

#[derive(Serialize)]
pub struct LoginPattern {
    pub pattern_type: String,
    pub count: i64,
    pub trend: String,
}

#[derive(Serialize)]
pub struct FailureAnalysis {
    pub failure_reason: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct GeographicMetric {
    pub country: String,
    pub region: String,
    pub count: i64,
}

#[derive(Serialize)]
pub struct FrequencyMetric {
    pub frequency_range: String,
    pub user_count: i64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct RetentionMetrics {
    pub daily_retention: f64,
    pub weekly_retention: f64,
    pub monthly_retention: f64,
}

pub async fn get_audit_dashboard(
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditDashboard>> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(&db, &user_id, "audit.read");

    let days = query.days.unwrap_or(7);
    let start_time = Utc::now() - Duration::days(days);
    
    tracing::info!("Generating audit dashboard for {} days", days);

    let audit_service = AuditService::new(db.as_ref().clone());

    // Get total users
    let total_users = get_total_users(&db).await?;
    
    // Get active sessions
    let active_sessions = get_active_sessions_count(&db).await?;
    
    // Get failed logins in period
    let failed_logins = get_failed_logins_count(&db, start_time).await?;
    
    // Get locked accounts
    let locked_accounts = get_locked_accounts_count(&db).await?;
    
    // Get security events count
    let security_events = get_security_events_count(&db, start_time).await?;
    
    // Get top activities using audit service
    let top_activities = get_top_activities(&db, start_time).await?;
    
    // Get login trends (daily aggregation)
    let login_trends = get_login_trends(&db, start_time, days).await?;
    
    // Get security trends
    let security_trends = get_security_trends(&db, start_time, days).await?;

    let dashboard = AuditDashboard {
        period: format!("Last {} days", days),
        total_users,
        active_sessions,
        failed_logins,
        locked_accounts,
        security_events,
        top_activities,
        login_trends,
        security_trends,
    };

    Ok(Json(dashboard))
}

pub async fn get_security_metrics(
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<SecurityMetrics>> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(&db, &user_id, "security.read");

    let hours = query.hours.unwrap_or(24);
    let start_time = Utc::now() - Duration::hours(hours);
    
    tracing::info!("Generating security metrics for {} hours", hours);

    let audit_service = AuditService::new(db.as_ref().clone());

    let authentication_stats = audit_service.get_authentication_stats(start_time).await?;
    let lockout_stats = audit_service.get_lockout_stats(start_time).await?;
    let rate_limit_violations = audit_service.get_rate_limit_violations(start_time).await?;
    let permission_denials = audit_service.get_permission_denials(start_time).await?;
    let failed_login_by_ip = audit_service.get_failed_login_by_ip(start_time).await?;
    let suspicious_activities = audit_service.get_suspicious_activities(start_time).await?;

    let metrics = SecurityMetrics {
        period: format!("Last {} hours", hours),
        authentication_stats,
        lockout_stats,
        rate_limit_violations,
        permission_denials,
        failed_login_by_ip,
        suspicious_activities,
    };

    Ok(Json(metrics))
}

pub async fn get_activity_summary(
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<ActivitySummary>> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(&db, &user_id, "audit.read");

    let days = query.days.unwrap_or(7);
    let start_time = Utc::now() - Duration::days(days);
    
    tracing::info!("Generating activity summary for {} days", days);

    let audit_service = AuditService::new(db.as_ref().clone());

    let total_activities = get_total_activities_count(&db, start_time).await?;
    let by_category = audit_service.get_activities_by_category(start_time).await?;
    let by_status = audit_service.get_activities_by_status(start_time).await?;
    let top_users = audit_service.get_top_active_users(start_time).await?;
    let hourly_distribution = audit_service.get_hourly_activity_distribution(start_time).await?;

    let summary = ActivitySummary {
        period: format!("Last {} days", days),
        total_activities,
        by_category,
        by_status,
        top_users,
        hourly_distribution,
    };

    Ok(Json(summary))
}

pub async fn get_system_health(
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
) -> ApiResult<Json<SystemHealth>> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(&db, &user_id, "security.read");
    
    tracing::info!("Checking system health");

    let database_status = check_database_health(&db).await?;
    let active_sessions_count = get_active_sessions_count(&db).await?;
    let pending_lockouts = get_pending_lockouts_count(&db).await?;
    let memory_usage = get_memory_usage().await;
    let uptime_seconds = get_uptime_seconds();

    let health = SystemHealth {
        timestamp: Utc::now(),
        database_status,
        active_sessions_count,
        pending_lockouts,
        memory_usage,
        uptime_seconds,
    };

    Ok(Json(health))
}

pub async fn generate_security_report(
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<SecurityReport>> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(&db, &user_id, "audit.read");

    let days = query.days.unwrap_or(30);
    let start_time = Utc::now() - Duration::days(days);
    
    tracing::info!("Generating comprehensive security report for {} days", days);

    let audit_service = AuditService::new(db.as_ref().clone());

    let executive_summary = audit_service.generate_executive_summary(start_time).await?;
    let authentication_analysis = generate_authentication_analysis(&db, start_time).await?;
    let security_incidents = get_security_incidents(&db, start_time).await?;
    let user_behavior_analysis = generate_user_behavior_analysis(&db, start_time).await?;
    let recommendations = audit_service.generate_security_recommendations(start_time).await?;

    let report = SecurityReport {
        generated_at: Utc::now(),
        period: format!("Last {} days", days),
        executive_summary,
        authentication_analysis,
        security_incidents,
        user_behavior_analysis,
        recommendations,
    };

    Ok(Json(report))
}

// Helper functions for data aggregation (implementation details)
async fn get_total_users(db: &Database) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM user WHERE account_status != 'Deleted'";
    let mut result = db.client.query(query).await
        .map_err(|e| {
            tracing::error!("Failed to get total users: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract total users count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    Ok(count.unwrap_or(0))
}

async fn get_active_sessions_count(db: &Database) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM session WHERE expires_at > $now";
    let mut result = db.client.query(query)
        .bind(("now", Utc::now().timestamp()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get active sessions: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract active sessions count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    Ok(count.unwrap_or(0))
}

async fn get_failed_logins_count(db: &Database, start_time: DateTime<Utc>) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM user_activity WHERE action = 'login_failed' AND timestamp >= $start_time";
    let mut result = db.client.query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get failed logins count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract failed logins count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    Ok(count.unwrap_or(0))
}

async fn get_locked_accounts_count(db: &Database) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM account_lockout WHERE status = 'Locked' AND locked_until > $now";
    let mut result = db.client.query(query)
        .bind(("now", Utc::now()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get locked accounts count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract locked accounts count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    Ok(count.unwrap_or(0))
}

async fn get_security_events_count(db: &Database, start_time: DateTime<Utc>) -> ApiResult<i64> {
    let query = "SELECT count() as total FROM user_activity WHERE category = 'Security' AND timestamp >= $start_time";
    let mut result = db.client.query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get security events count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let count: Option<i64> = result.take("total").map_err(|e| {
        tracing::error!("Failed to extract security events count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    Ok(count.unwrap_or(0))
}

async fn get_top_activities(db: &Database, start_time: DateTime<Utc>) -> ApiResult<Vec<ActivityMetric>> {
    let query = "SELECT action, count() as count FROM user_activity WHERE timestamp >= $start_time GROUP BY action ORDER BY count DESC LIMIT 10";
    let mut result = db.client.query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get top activities: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let activities: Vec<(String, i64)> = result.take(0).map_err(|e| {
        tracing::error!("Failed to extract top activities: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    let total: i64 = activities.iter().map(|(_, count)| count).sum();
    
    Ok(activities.into_iter().map(|(action, count)| {
        ActivityMetric {
            action,
            count,
            percentage: if total > 0 { (count as f64 / total as f64) * 100.0 } else { 0.0 },
        }
    }).collect())
}

async fn get_login_trends(db: &Database, start_time: DateTime<Utc>, days: i64) -> ApiResult<Vec<TimeseriesData>> {
    let query = "SELECT time::floor(timestamp, 1d) as day, count() as count FROM user_activity WHERE action IN ['login_success', 'oauth_login'] AND timestamp >= $start_time GROUP BY day ORDER BY day";
    let mut result = db.client.query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get login trends: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let trends: Vec<(DateTime<Utc>, i64)> = result.take(0).map_err(|e| {
        tracing::error!("Failed to extract login trends: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    Ok(trends.into_iter().map(|(timestamp, value)| {
        TimeseriesData { timestamp, value }
    }).collect())
}

async fn get_security_trends(db: &Database, start_time: DateTime<Utc>, days: i64) -> ApiResult<Vec<TimeseriesData>> {
    let query = "SELECT time::floor(timestamp, 1d) as day, count() as count FROM user_activity WHERE category = 'Security' AND status IN ['Failed', 'Warning'] AND timestamp >= $start_time GROUP BY day ORDER BY day";
    let mut result = db.client.query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get security trends: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let trends: Vec<(DateTime<Utc>, i64)> = result.take(0).map_err(|e| {
        tracing::error!("Failed to extract security trends: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    Ok(trends.into_iter().map(|(timestamp, value)| {
        TimeseriesData { timestamp, value }
    }).collect())
}

// Helper functions - simplified implementations for now

async fn get_total_activities_count(db: &Database, start_time: DateTime<Utc>) -> ApiResult<i64> {
    let query = "SELECT count() as count FROM user_activity WHERE timestamp >= $start_time";
    let mut result = db.client.query(query)
        .bind(("start_time", start_time.timestamp()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get total activities count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let count: Option<i64> = result.take("count").map_err(|e| {
        tracing::error!("Failed to extract total activities count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    Ok(count.unwrap_or(0))
}

async fn check_database_health(db: &Database) -> ApiResult<DatabaseHealth> {
    let start = std::time::Instant::now();
    
    // Simple health check
    let query = "INFO FOR DB";
    let result = db.client.query(query).await;
    
    let response_time_ms = start.elapsed().as_millis() as i64;
    let connected = result.is_ok();
    
    Ok(DatabaseHealth {
        connected,
        response_time_ms,
        connection_pool_used: 1, // Simplified
        connection_pool_size: 10,
    })
}

async fn get_pending_lockouts_count(db: &Database) -> ApiResult<i64> {
    let query = "SELECT count() as count FROM account_lockout WHERE status = 'Locked' AND locked_until > $now";
    let mut result = db.client.query(query)
        .bind(("now", Utc::now()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to get pending lockouts count: {}", e);
            AuthError::DatabaseError("Query execution failed".to_string())
        })?;
    
    let count: Option<i64> = result.take("count").map_err(|e| {
        tracing::error!("Failed to extract pending lockouts count: {}", e);
        AuthError::DatabaseError("Query execution failed".to_string())
    })?;
    
    Ok(count.unwrap_or(0))
}

async fn get_memory_usage() -> MemoryStats {
    // Simplified memory stats - in production you'd use system APIs
    MemoryStats {
        used_mb: 128.0,
        available_mb: 512.0,
        usage_percentage: 25.0,
    }
}

fn get_uptime_seconds() -> i64 {
    // Simplified uptime - in production you'd track actual startup time
    3600 // 1 hour
}

async fn generate_authentication_analysis(_db: &Database, _start_time: DateTime<Utc>) -> ApiResult<AuthenticationAnalysis> {
    // Simplified implementation - to be enhanced later
    Ok(AuthenticationAnalysis {
        login_patterns: vec![
            LoginPattern {
                pattern_type: "Regular Login".to_string(),
                count: 100,
                trend: "Stable".to_string(),
            }
        ],
        failure_analysis: vec![
            FailureAnalysis {
                failure_reason: "Invalid Password".to_string(),
                count: 25,
                percentage: 75.0,
            }
        ],
        geographic_distribution: vec![
            GeographicMetric {
                country: "US".to_string(),
                region: "California".to_string(),
                count: 80,
            }
        ],
    })
}

async fn get_security_incidents(_db: &Database, _start_time: DateTime<Utc>) -> ApiResult<Vec<SecurityIncident>> {
    // Simplified implementation - to be enhanced later
    Ok(vec![
        SecurityIncident {
            id: "incident_001".to_string(),
            incident_type: "Multiple Failed Logins".to_string(),
            severity: "Medium".to_string(),
            affected_user: Some("user_123".to_string()),
            ip_address: "192.168.1.100".to_string(),
            description: "Multiple failed login attempts from same IP".to_string(),
            timestamp: Utc::now() - Duration::hours(2),
            resolved: false,
        }
    ])
}

async fn generate_user_behavior_analysis(_db: &Database, _start_time: DateTime<Utc>) -> ApiResult<UserBehaviorAnalysis> {
    // Simplified implementation - to be enhanced later
    Ok(UserBehaviorAnalysis {
        login_frequency_distribution: vec![
            FrequencyMetric {
                frequency_range: "Daily".to_string(),
                user_count: 50,
                percentage: 60.0,
            }
        ],
        peak_activity_hours: vec![9, 10, 11, 14, 15, 16],
        user_retention_metrics: RetentionMetrics {
            daily_retention: 85.0,
            weekly_retention: 70.0,
            monthly_retention: 60.0,
        },
    })
}