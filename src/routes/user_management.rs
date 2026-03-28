use axum::{
    extract::{Path, Query, Extension},
    routing::{get, post, put},
    Router, Json,
};
use std::sync::Arc;

use crate::{
    config::Config,
    error::AuthError,
    routes::rbac::ApiResponse,
    models::{
        user::{UpdateAccountStatusRequest, UserListRequest},
        user_profile::{CreateUserProfileRequest, UpdateUserProfileRequest},
        user_preferences::{CreateUserPreferencesRequest, UpdateUserPreferencesRequest},
        user_activity::ActivityLogRequest,
    },
    services::{auth::AuthService, database::Database, user_management::UserManagementService},
    utils::jwt::Claims,
    require_permission,
};

pub fn router() -> Router {
    Router::new()
        .route("/profile", post(create_user_profile))
        .route("/profile", get(get_user_profile))
        .route("/profile", put(update_user_profile))
        .route("/preferences", post(create_user_preferences))
        .route("/preferences", get(get_user_preferences))
        .route("/preferences", put(update_user_preferences))
        .route("/activity-log", get(get_user_activity_log))
        .route("/users", get(list_users))
        .route("/users/:user_id/status", put(update_user_account_status))
        .route("/users/:user_id/profile", get(get_user_profile_by_id))
        .route("/users/:user_id/preferences", get(get_user_preferences_by_id))
        .route("/users/:user_id/activity-log", get(get_user_activity_log_by_id))
}

// 用户档案管理
async fn create_user_profile(
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<CreateUserProfileRequest>,
) -> Result<Json<ApiResponse<crate::models::user_profile::UserProfileResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    let service = UserManagementService::new(db);
    let profile = service.create_user_profile(&user_id, request).await?;
    Ok(Json(ApiResponse::success(profile, "User profile created successfully")))
}

async fn get_user_profile(
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<Json<ApiResponse<crate::models::user_profile::UserProfileResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    let service = UserManagementService::new(db);
    let profile = service.get_user_profile(&user_id).await?;
    Ok(Json(ApiResponse::success(profile, "User profile retrieved successfully")))
}

async fn update_user_profile(
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<UpdateUserProfileRequest>,
) -> Result<Json<ApiResponse<crate::models::user_profile::UserProfileResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    let service = UserManagementService::new(db);
    let profile = service.update_user_profile(&user_id, request).await?;
    Ok(Json(ApiResponse::success(profile, "User profile updated successfully")))
}

// 用户偏好管理
async fn create_user_preferences(
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<CreateUserPreferencesRequest>,
) -> Result<Json<ApiResponse<crate::models::user_preferences::UserPreferencesResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    let service = UserManagementService::new(db);
    let preferences = service.create_user_preferences(&user_id, request).await?;
    Ok(Json(ApiResponse::success(preferences, "User preferences created successfully")))
}

async fn get_user_preferences(
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<Json<ApiResponse<crate::models::user_preferences::UserPreferencesResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    let service = UserManagementService::new(db);
    let preferences = service.get_user_preferences(&user_id).await?;
    Ok(Json(ApiResponse::success(preferences, "User preferences retrieved successfully")))
}

async fn update_user_preferences(
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<UpdateUserPreferencesRequest>,
) -> Result<Json<ApiResponse<crate::models::user_preferences::UserPreferencesResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    let service = UserManagementService::new(db);
    let preferences = service.update_user_preferences(&user_id, request).await?;
    Ok(Json(ApiResponse::success(preferences, "User preferences updated successfully")))
}

// 用户活动日志
async fn get_user_activity_log(
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    Query(request): Query<ActivityLogRequest>,
) -> Result<Json<ApiResponse<crate::models::user_activity::ActivityLogResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;

    let service = UserManagementService::new(db);
    let activity_log = service.get_user_activity_log(&user_id, request).await?;
    Ok(Json(ApiResponse::success(activity_log, "User activity log retrieved successfully")))
}

// 管理员功能
async fn list_users(
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    Query(request): Query<UserListRequest>,
) -> Result<Json<ApiResponse<crate::models::user::UserListResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(db, &user_id, "users.read");

    let service = UserManagementService::new(db);
    let users = service.list_users(request).await?;
    Ok(Json(ApiResponse::success(users, "Users retrieved successfully")))
}

async fn update_user_account_status(
    Path(user_id): Path<String>,
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<UpdateAccountStatusRequest>,
) -> Result<Json<ApiResponse<crate::models::user::AccountStatusResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(db, &current_user_id, "users.write");
    let current_user = auth_service.resolve_authenticated_user(&claims).await?;

    let service = UserManagementService::new(db);
    let response = service.update_account_status(&user_id, request, &current_user).await?;
    Ok(Json(ApiResponse::success(response, "Account status updated successfully")))
}

async fn get_user_profile_by_id(
    Path(user_id): Path<String>,
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<Json<ApiResponse<crate::models::user_profile::UserProfileResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(db, &current_user_id, "users.read");

    let service = UserManagementService::new(db);
    let profile = service.get_user_profile(&user_id).await?;
    Ok(Json(ApiResponse::success(profile, "User profile retrieved successfully")))
}

async fn get_user_preferences_by_id(
    Path(user_id): Path<String>,
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<Json<ApiResponse<crate::models::user_preferences::UserPreferencesResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(db, &current_user_id, "users.read");

    let service = UserManagementService::new(db);
    let preferences = service.get_user_preferences(&user_id).await?;
    Ok(Json(ApiResponse::success(preferences, "User preferences retrieved successfully")))
}

async fn get_user_activity_log_by_id(
    Path(user_id): Path<String>,
    claims: Claims,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    Query(request): Query<ActivityLogRequest>,
) -> Result<Json<ApiResponse<crate::models::user_activity::ActivityLogResponse>>, AuthError> {
    let auth_service = AuthService::new(db.clone(), config)?;
    let current_user_id = auth_service.resolve_authenticated_user_id(&claims).await?;
    require_permission!(db, &current_user_id, "audit.read");

    let service = UserManagementService::new(db);
    let activity_log = service.get_user_activity_log(&user_id, request).await?;
    Ok(Json(ApiResponse::success(activity_log, "User activity log retrieved successfully")))
}
