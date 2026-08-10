//! 运营看板。
//!
//! 原先这里还有群组 / 会话明细两组接口（社交功能，已随社交模块一并删除），
//! 并且**整组路由没有任何鉴权** —— 任何人都能拉全量用户与会话数据。
//! 现在只剩会员分布概览，且需要 `users.read` 权限。

use std::sync::Arc;

use axum::{http::StatusCode, response::Json, routing::get, Extension, Router};
use serde::Serialize;
use serde_json::json;

use crate::{
    models::user::User, require_permission_status, services::database::Database,
    utils::jwt::AuthedUser,
};

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: String,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T, message: &str) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: message.to_string(),
        }
    }
}

pub fn router() -> Router {
    Router::new().route("/memberships/overview", get(get_membership_overview))
}

async fn get_membership_overview(
    user: AuthedUser,
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let user_id = user.id().map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_permission_status!(db, &user_id, crate::models::permission::names::USERS_READ);

    let users: Vec<User> = db
        .query_take0_vec_no_bind(
            "membership_overview",
            "SELECT * FROM user WHERE account_status != 'Deleted'",
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut distribution = serde_json::Map::new();
    for level in ["FREE", "PRO", "PREMIUM", "ULTIMATE", "TEAM"] {
        distribution.insert(level.to_string(), json!(0));
    }
    for user in &users {
        let level = if user.membership_level.trim().is_empty() {
            "FREE".to_string()
        } else {
            user.membership_level.trim().to_ascii_uppercase()
        };
        let current = distribution
            .get(&level)
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        distribution.insert(level, json!(current + 1));
    }

    Ok(Json(ApiResponse::success(
        json!({
            "total_users": users.len(),
            "distribution": distribution,
            "limits": {
                "FREE": { "ai_limit": 1, "daily_messages": 10, "price": 0.0 },
                "PRO": { "ai_limit": 3, "daily_messages": 50, "price": 19.9 },
                "PREMIUM": { "ai_limit": 5, "daily_messages": 100, "price": 39.9 },
                "ULTIMATE": { "ai_limit": 7, "daily_messages": null, "price": 79.9 },
                "TEAM": { "ai_limit": 35, "daily_messages": null, "price": 299.9 }
            }
        }),
        "Membership overview retrieved successfully",
    )))
}
