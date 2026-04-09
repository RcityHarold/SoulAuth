use axum::{
    extract::Query,
    http::StatusCode,
    response::Json,
    routing::get,
    Extension, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use surrealdb::types::RecordId as Thing;

use crate::{
    models::{direct_chat::DirectConversation, group::SocialGroupRecord, user::User},
    services::database::Database,
    utils::record_id::record_id_key_to_string,
};

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub keyword: Option<String>,
    pub page: Option<usize>,
    pub limit: Option<usize>,
}

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
    Router::new()
        .route("/memberships/overview", get(get_membership_overview))
        .route("/groups", get(list_groups))
        .route("/groups/:id", get(get_group_detail))
        .route("/conversations", get(list_conversations))
        .route("/conversations/:id", get(get_conversation_detail))
}

async fn get_membership_overview(
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let users: Vec<User> = db
        .client
        .select("user")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiResponse::success(
        json!({
            "total_users": users.len(),
            "distribution": { "Unspecified": users.len() },
            "limits": {
                "free_ai_limit": 1,
                "pro_ai_limit": 3,
                "premium_ai_limit": 7
            }
        }),
        "Membership overview retrieved successfully",
    )))
}

async fn list_groups(
    Extension(db): Extension<Arc<Database>>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let keyword = query.keyword.unwrap_or_default().to_lowercase();
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).clamp(1, 100);

    let groups: Vec<SocialGroupRecord> = db
        .client
        .select("group")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut items = groups
        .into_iter()
        .filter_map(|group| {
            let id = group.id.as_ref().map(record_id_key_to_string)?;
            let name = group.name.clone();
            if !keyword.is_empty() && !id.to_lowercase().contains(&keyword) && !name.to_lowercase().contains(&keyword) {
                return None;
            }
            Some(json!({
                "id": id,
                "name": name,
                "group_type": group_type_label(group.group_type),
                "level": group.level,
                "owner_id": group.owner_id,
                "human_count": group.human_member_ids.len(),
                "ai_count": group.ai_member_ids.len(),
                "created_at": group.created_at,
            }))
        })
        .collect::<Vec<_>>();

    let total = items.len();
    let start = (page - 1) * limit;
    let data = items.drain(..).skip(start).take(limit).collect::<Vec<_>>();

    Ok(Json(ApiResponse::success(
        json!({ "items": data, "page": page, "limit": limit, "total": total }),
        "Groups retrieved successfully",
    )))
}

async fn get_group_detail(
    axum::extract::Path(id): axum::extract::Path<String>,
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let groups: Vec<SocialGroupRecord> = db
        .client
        .select("group")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let group = groups
        .into_iter()
        .find(|group| group.id.as_ref().map(record_id_key_to_string).as_deref() == Some(id.as_str()))
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(ApiResponse::success(
        json!({
            "id": group.id.as_ref().map(record_id_key_to_string),
            "name": group.name,
            "group_type": group_type_label(group.group_type),
            "level": group.level,
            "owner_id": group.owner_id,
            "admin_ids": group.admin_ids,
            "human_member_ids": group.human_member_ids,
            "ai_member_ids": group.ai_member_ids,
            "announcement": group.announcement,
            "description": group.description,
            "code": group.code,
            "created_at": group.created_at,
        }),
        "Group detail retrieved successfully",
    )))
}

async fn list_conversations(
    Extension(db): Extension<Arc<Database>>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let keyword = query.keyword.unwrap_or_default().to_lowercase();
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).clamp(1, 100);

    let conversations: Vec<DirectConversation> = db
        .client
        .select("direct_conversation")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut items = conversations
        .into_iter()
        .filter_map(|conv| {
            let id = conv.id.as_ref().map(record_id_key_to_string)?;
            let participants = vec![record_id_key_to_string(&conv.user_a), record_id_key_to_string(&conv.user_b)];
            if !keyword.is_empty()
                && !id.to_lowercase().contains(&keyword)
                && !participants.iter().any(|p| p.to_lowercase().contains(&keyword))
            {
                return None;
            }
            Some(json!({
                "id": id,
                "conversation_type": "direct",
                "participant_ids": participants,
                "created_at": conv.created_at,
                "updated_at": conv.updated_at,
                "message_count": 0,
            }))
        })
        .collect::<Vec<_>>();

    let total = items.len();
    let start = (page - 1) * limit;
    let data = items.drain(..).skip(start).take(limit).collect::<Vec<_>>();

    Ok(Json(ApiResponse::success(
        json!({ "items": data, "page": page, "limit": limit, "total": total }),
        "Conversations retrieved successfully",
    )))
}

async fn get_conversation_detail(
    axum::extract::Path(id): axum::extract::Path<String>,
    Extension(db): Extension<Arc<Database>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let conversations: Vec<DirectConversation> = db
        .client
        .select("direct_conversation")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let conv = conversations
        .into_iter()
        .find(|conv| conv.id.as_ref().map(record_id_key_to_string).as_deref() == Some(id.as_str()))
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(ApiResponse::success(
        json!({
            "id": conv.id.as_ref().map(record_id_key_to_string),
            "conversation_type": "direct",
            "participant_ids": [record_id_key_to_string(&conv.user_a), record_id_key_to_string(&conv.user_b)],
            "created_at": conv.created_at,
            "updated_at": conv.updated_at,
            "message_count": 0,
            "last_message_preview": null,
        }),
        "Conversation detail retrieved successfully",
    )))
}

fn group_type_label(value: u8) -> &'static str {
    match value {
        0 => "HumanGroup",
        1 => "AIBrainTrust",
        2 => "MixedCommunity",
        _ => "Unknown",
    }
}

#[allow(dead_code)]
fn record_id_string(id: &Thing) -> String {
    record_id_key_to_string(id)
}
