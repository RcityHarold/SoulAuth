use axum::{
    extract::{ConnectInfo, Extension, Path, Query},
    http::HeaderMap,
    routing::{get, post, put},
    Json, Router,
};
use std::{net::SocketAddr, sync::Arc};

use crate::{
    config::Config,
    error::AuthError,
    routes::auth::request_context,
    routes::rbac::ApiResponse,
    models::{
        user::{UpdateAccountStatusRequest, UserListRequest, UpdateMembershipRequest},
        user_profile::{CreateUserProfileRequest, UpdateUserProfileRequest},
        user_preferences::{CreateUserPreferencesRequest, UpdateUserPreferencesRequest},
        user_activity::ActivityLogRequest,
    },
    services::{
        auth_cache::AuthCache, database::Database, user_management::UserManagementService,
    },
    utils::jwt::AuthedUser,
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
        .route("/users/:user_id", get(get_user_by_id))
        .route("/users/:user_id/status", put(update_user_account_status))
        .route("/users/:user_id/membership", put(update_user_membership))
        .route("/users/:user_id/profile", get(get_user_profile_by_id))
        .route("/users/:user_id/preferences", get(get_user_preferences_by_id))
        .route("/users/:user_id/activity-log", get(get_user_activity_log_by_id))
}

// 用户档案管理
async fn create_user_profile(
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CreateUserProfileRequest>,
) -> Result<Json<ApiResponse<crate::models::user_profile::UserProfileResponse>>, AuthError> {
    let user_id = authed_user.id()?;

    let service = UserManagementService::new(db);
    let profile = service
        .create_user_profile(&user_id, request, &request_context(&addr, &headers, &config))
        .await?;
    Ok(Json(ApiResponse::success(profile, "User profile created successfully")))
}

async fn get_user_profile(
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<ApiResponse<crate::models::user_profile::UserProfileResponse>>, AuthError> {
    let user_id = authed_user.id()?;

    let service = UserManagementService::new(db);
    let profile = service.get_user_profile(&user_id).await?;
    Ok(Json(ApiResponse::success(profile, "User profile retrieved successfully")))
}

async fn update_user_profile(
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<UpdateUserProfileRequest>,
) -> Result<Json<ApiResponse<crate::models::user_profile::UserProfileResponse>>, AuthError> {
    let user_id = authed_user.id()?;

    let service = UserManagementService::new(db);
    let profile = service
        .update_user_profile(&user_id, request, &request_context(&addr, &headers, &config))
        .await?;
    Ok(Json(ApiResponse::success(profile, "User profile updated successfully")))
}

// 用户偏好管理
async fn create_user_preferences(
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CreateUserPreferencesRequest>,
) -> Result<Json<ApiResponse<crate::models::user_preferences::UserPreferencesResponse>>, AuthError> {
    let user_id = authed_user.id()?;

    let service = UserManagementService::new(db);
    let preferences = service
        .create_user_preferences(&user_id, request, &request_context(&addr, &headers, &config))
        .await?;
    Ok(Json(ApiResponse::success(preferences, "User preferences created successfully")))
}

async fn get_user_preferences(
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<ApiResponse<crate::models::user_preferences::UserPreferencesResponse>>, AuthError> {
    let user_id = authed_user.id()?;

    let service = UserManagementService::new(db);
    let preferences = service.get_user_preferences(&user_id).await?;
    Ok(Json(ApiResponse::success(preferences, "User preferences retrieved successfully")))
}

async fn update_user_preferences(
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<UpdateUserPreferencesRequest>,
) -> Result<Json<ApiResponse<crate::models::user_preferences::UserPreferencesResponse>>, AuthError> {
    let user_id = authed_user.id()?;

    let service = UserManagementService::new(db);
    let preferences = service
        .update_user_preferences(&user_id, request, &request_context(&addr, &headers, &config))
        .await?;
    Ok(Json(ApiResponse::success(preferences, "User preferences updated successfully")))
}

// 用户活动日志
async fn get_user_activity_log(
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Query(request): Query<ActivityLogRequest>,
) -> Result<Json<ApiResponse<crate::models::user_activity::ActivityLogResponse>>, AuthError> {
    let user_id = authed_user.id()?;

    let service = UserManagementService::new(db);
    let activity_log = service.get_user_activity_log(&user_id, request).await?;
    Ok(Json(ApiResponse::success(activity_log, "User activity log retrieved successfully")))
}

// 管理员功能
async fn list_users(
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Query(request): Query<UserListRequest>,
) -> Result<Json<ApiResponse<crate::models::user::UserListResponse>>, AuthError> {
    let user_id = authed_user.id()?;
    require_permission!(db, &user_id, "users.read");

    let service = UserManagementService::new(db);
    let users = service.list_users(request).await?;
    Ok(Json(ApiResponse::success(users, "Users retrieved successfully")))
}

async fn update_user_account_status(
    Path(user_id): Path<String>,
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Extension(auth_cache): Extension<Arc<AuthCache>>,
    Extension(config): Extension<Config>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<UpdateAccountStatusRequest>,
) -> Result<Json<ApiResponse<crate::models::user::AccountStatusResponse>>, AuthError> {
    let current_user_id = authed_user.id()?;
    require_permission!(db, &current_user_id, "users.write");
    let current_user = authed_user.user().clone();

    let service = UserManagementService::new(db);
    let response = service
        .update_account_status(
            &user_id,
            request,
            &current_user,
            &request_context(&addr, &headers, &config),
        )
        .await?;

    // 停用 / 删除必须立刻生效，不能等鉴权缓存自然过期。
    auth_cache
        .invalidate_user(&crate::utils::record_id::normalize_user_id(&user_id))
        .await;

    Ok(Json(ApiResponse::success(response, "Account status updated successfully")))
}

async fn get_user_by_id(
    Path(user_id): Path<String>,
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<ApiResponse<crate::models::user::UserResponse>>, AuthError> {
    let current_user_id = authed_user.id()?;
    require_permission!(db, &current_user_id, "users.read");

    let service = UserManagementService::new(db);
    let user = service.get_user_by_id(&user_id).await?;
    Ok(Json(ApiResponse::success(user, "User retrieved successfully")))
}

async fn update_user_membership(
    Path(user_id): Path<String>,
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Json(request): Json<UpdateMembershipRequest>,
) -> Result<Json<ApiResponse<crate::models::user::UserResponse>>, AuthError> {
    let current_user_id = authed_user.id()?;
    require_permission!(db, &current_user_id, "users.write");

    let service = UserManagementService::new(db);
    let user = service.update_membership(&user_id, request).await?;
    Ok(Json(ApiResponse::success(user, "User membership updated successfully")))
}

async fn get_user_profile_by_id(
    Path(user_id): Path<String>,
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<ApiResponse<crate::models::user_profile::UserProfileResponse>>, AuthError> {
    let current_user_id = authed_user.id()?;
    require_permission!(db, &current_user_id, "users.read");

    let service = UserManagementService::new(db);
    let profile = service.get_user_profile(&user_id).await?;
    Ok(Json(ApiResponse::success(profile, "User profile retrieved successfully")))
}

async fn get_user_preferences_by_id(
    Path(user_id): Path<String>,
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<ApiResponse<crate::models::user_preferences::UserPreferencesResponse>>, AuthError> {
    let current_user_id = authed_user.id()?;
    require_permission!(db, &current_user_id, "users.read");

    let service = UserManagementService::new(db);
    let preferences = service.get_user_preferences(&user_id).await?;
    Ok(Json(ApiResponse::success(preferences, "User preferences retrieved successfully")))
}

async fn get_user_activity_log_by_id(
    Path(user_id): Path<String>,
    authed_user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
    Query(request): Query<ActivityLogRequest>,
) -> Result<Json<ApiResponse<crate::models::user_activity::ActivityLogResponse>>, AuthError> {
    let current_user_id = authed_user.id()?;
    require_permission!(db, &current_user_id, "audit.read");

    let service = UserManagementService::new(db);
    let activity_log = service.get_user_activity_log(&user_id, request).await?;
    Ok(Json(ApiResponse::success(activity_log, "User activity log retrieved successfully")))
}
