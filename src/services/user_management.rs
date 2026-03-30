use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    error::AuthError,
    models::{
        user::{User, AccountStatus, UpdateAccountStatusRequest, AccountStatusResponse, UserListRequest, UserListResponse, UserResponse},
        user_profile::{UserProfile, CreateUserProfileRequest, UpdateUserProfileRequest, UserProfileResponse},
        user_preferences::{UserPreferences, CreateUserPreferencesRequest, UpdateUserPreferencesRequest, UserPreferencesResponse},
        user_activity::{UserActivity, ActivityCategory, ActivityStatus, UserActivityResponse, ActivityLogRequest, ActivityLogResponse},
    },
    services::database::Database,
};

pub struct UserManagementService {
    db: Arc<Database>,
}

impl UserManagementService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    // 用户档案管理
    pub async fn create_user_profile(&self, user_id: &str, request: CreateUserProfileRequest) -> Result<UserProfileResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);
        
        // 检查用户是否存在
        let mut response = self.db.client
            .query("SELECT * FROM user WHERE id = $user_id LIMIT 1")
            .bind(("user_id", user_thing.clone()))
            .await
            .map_err(|e| {
                error!("Failed to check user existence: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let users: Vec<User> = response.take(0).map_err(|e| {
            error!("Failed to parse user: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if users.is_empty() {
            return Err(AuthError::NotFound("User not found".to_string()));
        }

        // 检查档案是否已存在
        let existing_profile = self.get_user_profile(user_id).await;
        if existing_profile.is_ok() {
            return Err(AuthError::ValidationError("User profile already exists".to_string()));
        }

        let now = Utc::now();
        let profile = UserProfile {
            id: None,
            user_id: user_thing,
            first_name: request.first_name,
            last_name: request.last_name,
            display_name: request.display_name,
            avatar_url: None,
            phone: request.phone,
            date_of_birth: request.date_of_birth,
            timezone: request.timezone,
            locale: request.locale,
            bio: request.bio,
            website: request.website,
            location: request.location,
            created_at: now,
            updated_at: now,
        };

        let query = "CREATE user_profile CONTENT $profile";
        let mut response = self.db.client
            .query(query)
            .bind(("profile", profile.clone()))
            .await
            .map_err(|e| {
                error!("Failed to create user profile: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created_profile: Vec<UserProfile> = response.take(0).map_err(|e| {
            error!("Failed to parse created profile: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created_profile.is_empty() {
            return Err(AuthError::DatabaseError("Failed to create user profile".to_string()));
        }

        // 记录活动
        self.log_user_activity(
            user_id,
            "profile_created",
            ActivityCategory::Profile,
            ActivityStatus::Success,
            "127.0.0.1",
            "System",
            serde_json::json!({"action": "profile_created"}),
        ).await?;

        info!("User profile created for user '{}'", user_id);
        Ok(created_profile[0].clone().into())
    }

    pub async fn get_user_profile(&self, user_id: &str) -> Result<UserProfileResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);
        
        let query = "SELECT * FROM user_profile WHERE user_id = $user_id";
        let mut response = self.db.client
            .query(query)
            .bind(("user_id", user_thing.clone()))
            .await
            .map_err(|e| {
                error!("Failed to get user profile: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let profiles: Vec<UserProfile> = response.take(0).map_err(|e| {
            error!("Failed to parse profile: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        profiles.into_iter().next()
            .map(|profile| profile.into())
            .ok_or_else(|| AuthError::NotFound("User profile not found".to_string()))
    }

    pub async fn update_user_profile(&self, user_id: &str, request: UpdateUserProfileRequest) -> Result<UserProfileResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);
        
        // 获取现有档案
        let existing_profile = self.get_user_profile(user_id).await?;
        
        let mut updates = Vec::new();
        if let Some(first_name) = &request.first_name {
            updates.push(format!("first_name = '{}'", first_name));
        }
        if let Some(last_name) = &request.last_name {
            updates.push(format!("last_name = '{}'", last_name));
        }
        if let Some(display_name) = &request.display_name {
            updates.push(format!("display_name = '{}'", display_name));
        }
        if let Some(phone) = &request.phone {
            updates.push(format!("phone = '{}'", phone));
        }
        if let Some(timezone) = &request.timezone {
            updates.push(format!("timezone = '{}'", timezone));
        }
        if let Some(locale) = &request.locale {
            updates.push(format!("locale = '{}'", locale));
        }
        if let Some(bio) = &request.bio {
            updates.push(format!("bio = '{}'", bio));
        }
        if let Some(website) = &request.website {
            updates.push(format!("website = '{}'", website));
        }
        if let Some(location) = &request.location {
            updates.push(format!("location = '{}'", location));
        }
        updates.push(format!("updated_at = {}", Utc::now().timestamp()));

        if updates.is_empty() {
            return Err(AuthError::ValidationError("No fields to update".to_string()));
        }

        let query = format!(
            "UPDATE user_profile SET {} WHERE user_id = $user_id",
            updates.join(", ")
        );
        
        let mut response = self.db.client
            .query(&query)
            .bind(("user_id", user_thing.clone()))
            .await
            .map_err(|e| {
                error!("Failed to update user profile: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let updated_profile: Vec<UserProfile> = response.take(0).map_err(|e| {
            error!("Failed to parse updated profile: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if updated_profile.is_empty() {
            return Err(AuthError::DatabaseError("Failed to update user profile".to_string()));
        }

        // 记录活动
        self.log_user_activity(
            user_id,
            "profile_updated",
            ActivityCategory::Profile,
            ActivityStatus::Success,
            "127.0.0.1",
            "System",
            serde_json::json!({"action": "profile_updated", "fields": updates}),
        ).await?;

        info!("User profile updated for user '{}'", user_id);
        Ok(updated_profile[0].clone().into())
    }

    // 用户偏好管理
    pub async fn create_user_preferences(&self, user_id: &str, request: CreateUserPreferencesRequest) -> Result<UserPreferencesResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);
        
        // 检查偏好是否已存在
        let existing_prefs = self.get_user_preferences(user_id).await;
        if existing_prefs.is_ok() {
            return Err(AuthError::ValidationError("User preferences already exist".to_string()));
        }

        let mut preferences = UserPreferences::default();
        preferences.user_id = user_thing;
        
        if let Some(theme) = request.theme {
            preferences.theme = theme;
        }
        if let Some(language) = request.language {
            preferences.language = language;
        }
        if let Some(email_notifications) = request.email_notifications {
            preferences.email_notifications = email_notifications;
        }
        if let Some(sms_notifications) = request.sms_notifications {
            preferences.sms_notifications = sms_notifications;
        }
        if let Some(marketing_emails) = request.marketing_emails {
            preferences.marketing_emails = marketing_emails;
        }
        if let Some(security_emails) = request.security_emails {
            preferences.security_emails = security_emails;
        }
        if let Some(newsletter) = request.newsletter {
            preferences.newsletter = newsletter;
        }
        if let Some(two_factor_required) = request.two_factor_required {
            preferences.two_factor_required = two_factor_required;
        }
        if let Some(session_timeout) = request.session_timeout {
            preferences.session_timeout = session_timeout;
        }
        if let Some(timezone) = request.timezone {
            preferences.timezone = timezone;
        }
        if let Some(date_format) = request.date_format {
            preferences.date_format = date_format;
        }
        if let Some(time_format) = request.time_format {
            preferences.time_format = time_format;
        }

        let query = "CREATE user_preferences CONTENT $preferences";
        let mut response = self.db.client
            .query(query)
            .bind(("preferences", preferences.clone()))
            .await
            .map_err(|e| {
                error!("Failed to create user preferences: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let created_preferences: Vec<UserPreferences> = response.take(0).map_err(|e| {
            error!("Failed to parse created preferences: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if created_preferences.is_empty() {
            return Err(AuthError::DatabaseError("Failed to create user preferences".to_string()));
        }

        // 记录活动
        self.log_user_activity(
            user_id,
            "preferences_created",
            ActivityCategory::Profile,
            ActivityStatus::Success,
            "127.0.0.1",
            "System",
            serde_json::json!({"action": "preferences_created"}),
        ).await?;

        info!("User preferences created for user '{}'", user_id);
        Ok(created_preferences[0].clone().into())
    }

    pub async fn get_user_preferences(&self, user_id: &str) -> Result<UserPreferencesResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);
        
        let query = "SELECT * FROM user_preferences WHERE user_id = $user_id";
        let mut response = self.db.client
            .query(query)
            .bind(("user_id", user_thing.clone()))
            .await
            .map_err(|e| {
                error!("Failed to get user preferences: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let preferences: Vec<UserPreferences> = response.take(0).map_err(|e| {
            error!("Failed to parse preferences: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        preferences.into_iter().next()
            .map(|prefs| prefs.into())
            .ok_or_else(|| AuthError::NotFound("User preferences not found".to_string()))
    }

    pub async fn update_user_preferences(&self, user_id: &str, request: UpdateUserPreferencesRequest) -> Result<UserPreferencesResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);
        
        // 获取现有偏好
        let _existing_prefs = self.get_user_preferences(user_id).await?;
        
        let mut updates = Vec::new();
        if let Some(theme) = &request.theme {
            updates.push(format!("theme = '{}'", theme));
        }
        if let Some(language) = &request.language {
            updates.push(format!("language = '{}'", language));
        }
        if let Some(email_notifications) = request.email_notifications {
            updates.push(format!("email_notifications = {}", email_notifications));
        }
        if let Some(sms_notifications) = request.sms_notifications {
            updates.push(format!("sms_notifications = {}", sms_notifications));
        }
        if let Some(marketing_emails) = request.marketing_emails {
            updates.push(format!("marketing_emails = {}", marketing_emails));
        }
        if let Some(security_emails) = request.security_emails {
            updates.push(format!("security_emails = {}", security_emails));
        }
        if let Some(newsletter) = request.newsletter {
            updates.push(format!("newsletter = {}", newsletter));
        }
        if let Some(two_factor_required) = request.two_factor_required {
            updates.push(format!("two_factor_required = {}", two_factor_required));
        }
        if let Some(session_timeout) = request.session_timeout {
            updates.push(format!("session_timeout = {}", session_timeout));
        }
        if let Some(timezone) = &request.timezone {
            updates.push(format!("timezone = '{}'", timezone));
        }
        if let Some(date_format) = &request.date_format {
            updates.push(format!("date_format = '{}'", date_format));
        }
        if let Some(time_format) = &request.time_format {
            updates.push(format!("time_format = '{}'", time_format));
        }
        updates.push(format!("updated_at = {}", Utc::now().timestamp()));

        if updates.is_empty() {
            return Err(AuthError::ValidationError("No fields to update".to_string()));
        }

        let query = format!(
            "UPDATE user_preferences SET {} WHERE user_id = $user_id",
            updates.join(", ")
        );
        
        let mut response = self.db.client
            .query(&query)
            .bind(("user_id", user_thing.clone()))
            .await
            .map_err(|e| {
                error!("Failed to update user preferences: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let updated_preferences: Vec<UserPreferences> = response.take(0).map_err(|e| {
            error!("Failed to parse updated preferences: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if updated_preferences.is_empty() {
            return Err(AuthError::DatabaseError("Failed to update user preferences".to_string()));
        }

        // 记录活动
        self.log_user_activity(
            user_id,
            "preferences_updated",
            ActivityCategory::Profile,
            ActivityStatus::Success,
            "127.0.0.1",
            "System",
            serde_json::json!({"action": "preferences_updated", "fields": updates}),
        ).await?;

        info!("User preferences updated for user '{}'", user_id);
        Ok(updated_preferences[0].clone().into())
    }

    // 账户状态管理
    pub async fn update_account_status(&self, user_id: &str, request: UpdateAccountStatusRequest, updated_by: &User) -> Result<AccountStatusResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);
        
        // 检查用户是否存在
        let mut response = self.db.client
            .query("SELECT * FROM user WHERE id = $user_id LIMIT 1")
            .bind(("user_id", user_thing.clone()))
            .await
            .map_err(|e| {
                error!("Failed to check user existence: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let users: Vec<User> = response.take(0).map_err(|e| {
            error!("Failed to parse user: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        if users.is_empty() {
            return Err(AuthError::NotFound("User not found".to_string()));
        }

        let now = Utc::now();

        self.db.client
            .query("UPDATE user SET account_status = $status, updated_at = $updated_at WHERE id = $user_id")
            .bind(("status", request.status.to_string()))
            .bind(("updated_at", now.timestamp()))
            .bind(("user_id", user_thing.clone()))
            .await
            .map_err(|e| {
                error!("Failed to update account status: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        // 记录活动
        self.log_user_activity(
            user_id,
            "account_status_changed",
            ActivityCategory::Security,
            ActivityStatus::Success,
            "127.0.0.1",
            "System",
            serde_json::json!({
                "action": "account_status_changed",
                "old_status": users[0].account_status,
                "new_status": request.status,
                "reason": request.reason
            }),
        ).await?;

        info!("Account status updated for user '{}' to {:?} by '{}'", user_id, request.status, updated_by.email);
        
        Ok(AccountStatusResponse {
            user_id: user_id.to_string(),
            status: request.status,
            updated_at: now,
            updated_by: updated_by.email.clone(),
            reason: request.reason,
        })
    }

    // 用户活动日志
    pub async fn log_user_activity(
        &self,
        user_id: &str,
        action: &str,
        category: ActivityCategory,
        status: ActivityStatus,
        ip_address: &str,
        user_agent: &str,
        details: serde_json::Value,
    ) -> Result<(), AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);
        
        let activity = UserActivity {
            id: None,
            user_id: user_thing,
            action: action.to_string(),
            category,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            details,
            status,
            timestamp: Utc::now(),
        };

        let query = "CREATE user_activity CONTENT $activity";
        self.db.client
            .query(query)
            .bind(("activity", activity.clone()))
            .await
            .map_err(|e| {
                error!("Failed to log user activity: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    pub async fn get_user_activity_log(&self, user_id: &str, request: ActivityLogRequest) -> Result<ActivityLogResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);
        let page = request.page.unwrap_or(1);
        let limit = request.limit.unwrap_or(50);
        let offset = (page - 1) * limit;

        let mut where_clauses = vec!["user_id = $user_id".to_string()];
        
        if let Some(category) = &request.category {
            where_clauses.push(format!("category = '{:?}'", category));
        }
        if let Some(status) = &request.status {
            where_clauses.push(format!("status = '{:?}'", status));
        }
        if let Some(start_date) = request.start_date {
            where_clauses.push(format!("timestamp >= {}", start_date.timestamp()));
        }
        if let Some(end_date) = request.end_date {
            where_clauses.push(format!("timestamp <= {}", end_date.timestamp()));
        }

        let query = format!(
            "SELECT * FROM user_activity WHERE {} ORDER BY timestamp DESC LIMIT {} START {}",
            where_clauses.join(" AND "),
            limit,
            offset
        );

        let mut response = self.db.client
            .query(&query)
            .bind(("user_id", user_thing.clone()))
            .await
            .map_err(|e| {
                error!("Failed to get user activity log: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let activities: Vec<UserActivity> = response.take(0).map_err(|e| {
            error!("Failed to parse activities: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        // 获取总数
        let count_query = format!(
            "SELECT count() as total FROM user_activity WHERE {} GROUP ALL",
            where_clauses.join(" AND ")
        );

        let mut count_response = self.db.client
            .query(&count_query)
            .bind(("user_id", user_thing.clone()))
            .await
            .map_err(|e| {
                error!("Failed to count activities: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let count_result: Vec<serde_json::Value> = count_response.take(0).map_err(|e| {
            error!("Failed to parse count: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        let total = count_result.first()
            .and_then(|c| c.get("total"))
            .and_then(|t| t.as_u64())
            .unwrap_or(0);

        let total_pages = (total as f64 / limit as f64).ceil() as u32;

        Ok(ActivityLogResponse {
            activities: activities.into_iter().map(|a| a.into()).collect(),
            total,
            page,
            limit,
            total_pages,
        })
    }

    // 用户列表管理
    pub async fn list_users(&self, request: UserListRequest) -> Result<UserListResponse, AuthError> {
        let page = request.page.unwrap_or(1);
        let limit = request.limit.unwrap_or(50);
        let offset = (page - 1) * limit;

        let mut where_clauses = Vec::new();
        
        if let Some(status) = &request.status {
            where_clauses.push(format!("account_status = '{:?}'", status));
        }
        if let Some(search) = &request.search {
            where_clauses.push(format!("email CONTAINS '{}'", search));
        }

        let where_clause = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let sort_by = request.sort_by.unwrap_or("created_at".to_string());
        let sort_order = request.sort_order.unwrap_or("DESC".to_string());

        let query = format!(
            "SELECT * FROM user {} ORDER BY {} {} LIMIT {} START {}",
            where_clause,
            sort_by,
            sort_order,
            limit,
            offset
        );

        let mut response = self.db.client
            .query(&query)
            .await
            .map_err(|e| {
                error!("Failed to list users: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let users: Vec<User> = response.take(0).map_err(|e| {
            error!("Failed to parse users: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        // 获取总数
        let count_query = format!("SELECT count() as total FROM user {} GROUP ALL", where_clause);
        
        let mut count_response = self.db.client
            .query(&count_query)
            .await
            .map_err(|e| {
                error!("Failed to count users: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let count_result: Vec<serde_json::Value> = count_response.take(0).map_err(|e| {
            error!("Failed to parse count: {}", e);
            AuthError::DatabaseError(e.to_string())
        })?;

        let total = count_result.first()
            .and_then(|c| c.get("total"))
            .and_then(|t| t.as_u64())
            .unwrap_or(0);

        let total_pages = (total as f64 / limit as f64).ceil() as u32;

        Ok(UserListResponse {
            users: users.into_iter().map(|u| u.into()).collect(),
            total,
            page,
            limit,
            total_pages,
        })
    }
}
