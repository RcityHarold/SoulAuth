use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    error::AuthError,
    models::{
        user::{User, UpdateAccountStatusRequest, AccountStatusResponse, UserListRequest, UserListResponse, UserResponse, UpdateMembershipRequest},
        user_profile::{UserProfile, CreateUserProfileRequest, UpdateUserProfileRequest, UserProfileResponse},
        user_preferences::{UserPreferences, CreateUserPreferencesRequest, UpdateUserPreferencesRequest, UserPreferencesResponse},
        user_activity::{
            ActivityCategory, ActivityLogRequest, ActivityLogResponse, ActivityStatus,
            UserActivityResponse, UserActivityRow,
        },
    },
    services::{
        audit_logger::{AuditEvent, AuditLogger},
        auth::RequestContext,
        database::Database,
        rbac::RBACService,
    },
};

pub struct UserManagementService {
    db: Arc<Database>,
}

impl UserManagementService {
    fn normalize_membership_level(level: &str) -> Result<String, AuthError> {
        match level.trim().to_ascii_uppercase().as_str() {
            "FREE" | "PRO" | "PREMIUM" | "ULTIMATE" | "TEAM" => Ok(level.trim().to_ascii_uppercase()),
            _ => Err(AuthError::ValidationError("Invalid membership level".to_string())),
        }
    }

    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    // 用户档案管理
    pub async fn create_user_profile(
        &self,
        user_id: &str,
        request: CreateUserProfileRequest,
        ctx: &RequestContext,
    ) -> Result<UserProfileResponse, AuthError> {
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

        let now = Utc::now().timestamp();
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
            &ctx.ip_address,
            &ctx.user_agent,
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

    pub async fn update_user_profile(
        &self,
        user_id: &str,
        request: UpdateUserProfileRequest,
        ctx: &RequestContext,
    ) -> Result<UserProfileResponse, AuthError> {
        // 档案不存在时先报 404，而不是让 UPDATE 静默命中 0 行。
        self.get_user_profile(user_id).await?;
        
        // 全部走绑定参数。以前这里把 bio / website / display_name 等用户可控字段
        // 直接内插进 SurrealQL，一个单引号就能改写整条语句。
        // `$x ?? field` 表示"传了就更新，没传就保持原值"。
        let query = r#"
            UPDATE user_profile SET
                first_name = $first_name ?? first_name,
                last_name = $last_name ?? last_name,
                display_name = $display_name ?? display_name,
                phone = $phone ?? phone,
                timezone = $timezone ?? timezone,
                locale = $locale ?? locale,
                bio = $bio ?? bio,
                website = $website ?? website,
                location = $location ?? location,
                updated_at = $updated_at
            WHERE user_id = type::record('user', $user_key)
        "#;

        let bindings = serde_json::json!({
            "user_key": crate::utils::record_id::normalize_user_id(user_id),
            "first_name": request.first_name,
            "last_name": request.last_name,
            "display_name": request.display_name,
            "phone": request.phone,
            "timezone": request.timezone,
            "locale": request.locale,
            "bio": request.bio,
            "website": request.website,
            "location": request.location,
            "updated_at": Utc::now().timestamp(),
        });

        let mut response = self
            .db
            .raw_query("update_user_profile", query, bindings)
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
            &ctx.ip_address,
            &ctx.user_agent,
            serde_json::json!({"action": "profile_updated"}),
        ).await?;

        info!("User profile updated for user '{}'", user_id);
        Ok(updated_profile[0].clone().into())
    }

    // 用户偏好管理
    pub async fn create_user_preferences(
        &self,
        user_id: &str,
        request: CreateUserPreferencesRequest,
        ctx: &RequestContext,
    ) -> Result<UserPreferencesResponse, AuthError> {
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
            &ctx.ip_address,
            &ctx.user_agent,
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

    pub async fn update_user_preferences(
        &self,
        user_id: &str,
        request: UpdateUserPreferencesRequest,
        ctx: &RequestContext,
    ) -> Result<UserPreferencesResponse, AuthError> {
        // 偏好不存在时先报 404。
        self.get_user_preferences(user_id).await?;
        
        // 同上：改为全绑定参数。
        let query = r#"
            UPDATE user_preferences SET
                theme = $theme ?? theme,
                language = $language ?? language,
                email_notifications = $email_notifications ?? email_notifications,
                sms_notifications = $sms_notifications ?? sms_notifications,
                marketing_emails = $marketing_emails ?? marketing_emails,
                security_emails = $security_emails ?? security_emails,
                newsletter = $newsletter ?? newsletter,
                two_factor_required = $two_factor_required ?? two_factor_required,
                session_timeout = $session_timeout ?? session_timeout,
                timezone = $timezone ?? timezone,
                date_format = $date_format ?? date_format,
                time_format = $time_format ?? time_format,
                updated_at = $updated_at
            WHERE user_id = type::record('user', $user_key)
        "#;

        let bindings = serde_json::json!({
            "user_key": crate::utils::record_id::normalize_user_id(user_id),
            "theme": request.theme,
            "language": request.language,
            "email_notifications": request.email_notifications,
            "sms_notifications": request.sms_notifications,
            "marketing_emails": request.marketing_emails,
            "security_emails": request.security_emails,
            "newsletter": request.newsletter,
            "two_factor_required": request.two_factor_required,
            "session_timeout": request.session_timeout,
            "timezone": request.timezone,
            "date_format": request.date_format,
            "time_format": request.time_format,
            "updated_at": Utc::now().timestamp(),
        });

        let mut response = self
            .db
            .raw_query("update_user_preferences", query, bindings)
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
            &ctx.ip_address,
            &ctx.user_agent,
            serde_json::json!({"action": "preferences_updated"}),
        ).await?;

        info!("User preferences updated for user '{}'", user_id);
        Ok(updated_preferences[0].clone().into())
    }

    // 账户状态管理
    pub async fn update_account_status(
        &self,
        user_id: &str,
        request: UpdateAccountStatusRequest,
        updated_by: &User,
        ctx: &RequestContext,
    ) -> Result<AccountStatusResponse, AuthError> {
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
            &ctx.ip_address,
            &ctx.user_agent,
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
    /// 记录一条用户活动。
    ///
    /// 直接复用 `AuditLogger` 的写入路径，**不再自己拼一套**。以前这里用
    /// `.bind(("activity", ...))` 走 SurrealValue 编码，而 `audit_logger`
    /// 走 serde（枚举存成纯字符串），同一张 `user_activity` 表上出现了两种
    /// 互不兼容的编码：读取端只认其中一种，另一种写进去的行读不出来
    /// —— 而且 SurrealValue 编码的枚举很可能根本过不了 `TYPE string` 的校验。
    ///
    /// 写入是 fire-and-forget，失败只记日志：不能因为写不进审计日志
    /// 就让改档案 / 改状态这类业务操作整体失败。
    pub async fn log_user_activity(
        &self,
        user_id: &str,
        action: &'static str,
        category: ActivityCategory,
        status: ActivityStatus,
        ip_address: &str,
        user_agent: &str,
        details: serde_json::Value,
    ) -> Result<(), AuthError> {
        AuditLogger::new(self.db.clone()).record(
            AuditEvent::new(action, category, status, ip_address, user_agent)
                .with_user(user_id)
                .with_details(details),
        );

        Ok(())
    }

    /// 查询某用户的活动日志。
    ///
    /// 读取走 serde（与 `AuditLogger` 的写入编码一致）。以前这里用
    /// `take::<Vec<UserActivity>>` 走 SurrealValue 解码，而写入端存的是
    /// 纯字符串枚举，两边对不上会直接解码失败。
    ///
    /// 过滤条件全部走绑定参数：`category` / `status` 虽然是枚举（不可注入），
    /// 但没有理由再留一处字符串拼接。
    pub async fn get_user_activity_log(
        &self,
        user_id: &str,
        request: ActivityLogRequest,
    ) -> Result<ActivityLogResponse, AuthError> {
        let page = request.page.unwrap_or(1).max(1);
        let limit = request.limit.unwrap_or(50).clamp(1, 200);
        let offset = (page - 1) * limit;

        let mut where_clauses = vec!["user_id = type::record('user', $user_key)".to_string()];
        if request.category.is_some() {
            where_clauses.push("category = $category".to_string());
        }
        if request.status.is_some() {
            where_clauses.push("status = $status".to_string());
        }
        if request.start_date.is_some() {
            where_clauses.push("timestamp >= $start_ts".to_string());
        }
        if request.end_date.is_some() {
            where_clauses.push("timestamp <= $end_ts".to_string());
        }
        let where_clause = where_clauses.join(" AND ");

        let bindings = json!({
            "user_key": crate::utils::record_id::normalize_user_id(user_id),
            "category": request.category.as_ref().map(|c| format!("{c:?}")),
            "status": request.status.as_ref().map(|s| format!("{s:?}")),
            "start_ts": request.start_date.map(|d| d.timestamp()),
            "end_ts": request.end_date.map(|d| d.timestamp()),
            "limit": limit,
            "offset": offset,
        });

        // id / user_id 是 record 链接，投影成字符串才能走 serde。
        let query = format!(
            "SELECT type::string(id) AS id, \
                    IF user_id = NONE {{ NONE }} ELSE {{ type::string(user_id) }} AS user_id, \
                    action, category, ip_address, user_agent, details, status, timestamp \
             FROM user_activity WHERE {where_clause} \
             ORDER BY timestamp DESC LIMIT $limit START $offset"
        );

        let rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec("user_activity_log", &query, bindings.clone())
            .await
            .map_err(|e| {
                error!("Failed to get user activity log: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let activities = rows
            .into_iter()
            .map(serde_json::from_value::<UserActivityRow>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                error!("Failed to parse activities: {}", e);
                AuthError::DatabaseError(format!("Failed to parse activities: {e}"))
            })?
            .into_iter()
            .map(UserActivityResponse::from)
            .collect::<Vec<_>>();

        let count_query =
            format!("SELECT count() AS total FROM user_activity WHERE {where_clause} GROUP ALL");
        let count_rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec("user_activity_log_count", &count_query, bindings)
            .await
            .map_err(|e| {
                error!("Failed to count activities: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let total = count_rows
            .first()
            .and_then(|c| c.get("total"))
            .and_then(|t| t.as_u64())
            .unwrap_or(0);

        Ok(ActivityLogResponse {
            activities,
            total,
            page,
            limit,
            total_pages: (total as f64 / limit as f64).ceil() as u32,
        })
    }

    // 用户列表管理
    pub async fn get_user_by_id(&self, user_id: &str) -> Result<UserResponse, AuthError> {
        let user_thing = crate::utils::record_id::user_record_id(user_id);

        let users: Vec<User> = self
            .db
            .query_take0_vec(
                "user_management_get_user_by_id",
                "SELECT * FROM user WHERE id = $user_id LIMIT 1",
                json!({ "user_id": user_thing }),
            )
            .await
            .map_err(|e| {
                error!("Failed to get user by id: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let user = users.into_iter().next()
            .ok_or_else(|| AuthError::NotFound("User not found".to_string()))?;

        let mut response: UserResponse = user.into();
        response.is_admin = self.user_has_admin_role(user_id).await?;
        Ok(response)
    }

    async fn user_has_admin_role(&self, user_id: &str) -> Result<bool, AuthError> {
        let rbac = RBACService::new(self.db.clone());
        rbac.check_user_role(user_id, "admin").await
    }

    pub async fn list_users(&self, request: UserListRequest) -> Result<UserListResponse, AuthError> {
        let page = request.page.unwrap_or(1);
        let limit = request.limit.unwrap_or(50);
        let offset = (page - 1) * limit;

        // 过滤条件全部走绑定参数：`search` 是用户可控的自由文本，以前直接拼进
        // `email CONTAINS '...'`，单引号即可改写语句。
        let mut where_clauses = Vec::new();
        if request.status.is_some() {
            where_clauses.push("account_status = $status");
        }
        if request.search.is_some() {
            where_clauses.push("string::contains(email, $search)");
        }

        let where_clause = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        // 排序字段无法参数化，因此只接受白名单内的取值。
        let sort_by = match request.sort_by.as_deref() {
            Some("email") => "email",
            Some("username") => "username",
            Some("updated_at") => "updated_at",
            Some("last_login_at") => "last_login_at",
            _ => "created_at",
        };
        let sort_order = match request.sort_order.as_deref() {
            Some(order) if order.eq_ignore_ascii_case("asc") => "ASC",
            _ => "DESC",
        };

        let bindings = json!({
            "status": request.status.as_ref().map(|status| format!("{status:?}")),
            "search": request.search,
            "limit": limit,
            "offset": offset,
        });

        let query = format!(
            "SELECT * FROM user {where_clause} ORDER BY {sort_by} {sort_order} LIMIT $limit START $offset"
        );

        let users: Vec<User> = self
            .db
            .query_take0_vec("user_management_list_users", &query, bindings.clone())
            .await
            .map_err(|e| {
                error!("Failed to list users: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        // 获取总数
        let count_query = format!("SELECT count() as total FROM user {where_clause} GROUP ALL");

        let count_result: Vec<serde_json::Value> = self
            .db
            .query_take0_vec("user_management_count_users", &count_query, bindings)
            .await
            .map_err(|e| {
                error!("Failed to count users: {}", e);
                AuthError::DatabaseError(e.to_string())
            })?;

        let total = count_result.first()
            .and_then(|c| c.get("total"))
            .and_then(|t| t.as_u64())
            .unwrap_or(0);

        let total_pages = (total as f64 / limit as f64).ceil() as u32;

        let mut user_responses = Vec::with_capacity(users.len());
        for user in users {
            let user_id = crate::utils::record_id::record_id_key_to_string(user.id.as_ref().ok_or_else(|| {
                AuthError::DatabaseError("User missing id".to_string())
            })?);
            let mut response: UserResponse = user.into();
            response.is_admin = self.user_has_admin_role(&user_id).await?;
            user_responses.push(response);
        }

        Ok(UserListResponse {
            users: user_responses,
            total,
            page,
            limit,
            total_pages,
        })
    }

    pub async fn update_membership(
        &self,
        user_id: &str,
        request: UpdateMembershipRequest,
    ) -> Result<UserResponse, AuthError> {
        let mut user = self
            .db
            .find_record_by_field::<User>("user", "id", user_id)
            .await?
            .ok_or_else(|| AuthError::NotFound("User not found".to_string()))?;

        user.membership_level = Self::normalize_membership_level(&request.membership_level)?;
        user.membership_expiry = request
            .membership_expiry
            .and_then(|value| {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() { None } else { Some(trimmed) }
            });
        user.updated_at = chrono::Utc::now().timestamp();

        let user_thing = user
            .id
            .as_ref()
            .ok_or_else(|| AuthError::DatabaseError("User missing id".to_string()))?;
        let updated = self
            .db
            .update_record(
                "user",
                &format!(
                    "{}:{}",
                    user_thing.table,
                    crate::utils::record_id::record_id_key_to_string(user_thing)
                ),
                &user,
            )
            .await?;

        let updated_id = crate::utils::record_id::record_id_key_to_string(
            updated
                .id
                .as_ref()
                .ok_or_else(|| AuthError::DatabaseError("Updated user missing id".to_string()))?
        );
        let mut response: UserResponse = updated.into();
        response.is_admin = self
            .user_has_admin_role(&updated_id)
            .await?;
        Ok(response)
    }
}
