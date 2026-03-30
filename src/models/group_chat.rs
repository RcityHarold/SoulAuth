use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct GroupThread {
    pub id: Option<Thing>,
    pub group_id: String,
    pub thread_type: String,
    pub title: String,
    pub created_by: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct GroupThreadMessage {
    pub id: Option<Thing>,
    pub group_id: String,
    pub thread_id: String,
    pub sender_id: String,
    pub sender_kind: String,
    pub message_type: String,
    pub content: String,
    pub reply_to: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupThreadRequest {
    pub title: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendGroupThreadMessageRequest {
    pub content: String,
    pub reply_to: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupThreadView {
    pub id: String,
    pub group_id: String,
    pub thread_type: String,
    pub title: String,
    pub created_by: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupThreadMessageView {
    pub id: String,
    pub group_id: String,
    pub thread_id: String,
    pub sender_id: String,
    pub sender_kind: String,
    pub message_type: String,
    pub content: String,
    pub reply_to: Option<String>,
    pub created_at: String,
}
