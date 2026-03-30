use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct DirectConversation {
    pub id: Option<Thing>,
    pub user_a: Thing,
    pub user_b: Thing,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct DirectMessage {
    pub id: Option<Thing>,
    pub conversation_id: Thing,
    pub sender_id: Thing,
    pub recipient_id: Thing,
    pub content: String,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnsureDirectConversationRequest {
    pub target_user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendDirectMessageRequest {
    pub conversation_id: Option<String>,
    pub target_user_id: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirectConversationView {
    pub conversation_id: String,
    pub peer_user_id: String,
    pub peer_username: String,
    pub last_message: Option<String>,
    pub last_message_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DirectMessageView {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub content: String,
    pub created_at: String,
}
