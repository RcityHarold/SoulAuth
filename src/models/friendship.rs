use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, SurrealValue)]
pub enum FriendRequestStatus {
    Pending,
    Accepted,
    Rejected,
    Cancelled,
}

impl FriendRequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Accepted => "Accepted",
            Self::Rejected => "Rejected",
            Self::Cancelled => "Cancelled",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct FriendRequest {
    pub id: Option<Thing>,
    pub requester_id: Thing,
    pub addressee_id: Thing,
    pub status: String,
    pub message: Option<String>,
    pub created_at: i64,
    pub responded_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct Friendship {
    pub id: Option<Thing>,
    pub user_a: Thing,
    pub user_b: Thing,
    pub created_at: i64,
    pub created_from_request_id: Option<Thing>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendFriendRequestRequest {
    pub target_user_id: String,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RespondFriendRequestRequest {
    pub accept: bool,
}

#[derive(Debug, Serialize)]
pub struct FriendRequestActionResponse {
    pub request_id: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct FriendRequestView {
    pub request_id: String,
    pub requester_id: String,
    pub requester_username: String,
    pub addressee_id: String,
    pub addressee_username: String,
    pub status: String,
    pub message: Option<String>,
    pub created_at: i64,
    pub responded_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct FriendView {
    pub user_id: String,
    pub username: String,
    pub created_at: i64,
}
