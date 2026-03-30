use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct SocialGroupMember {
    pub id: Option<Thing>,
    pub group_id: String,
    pub member_id: String,
    pub member_kind: String,
    pub created_at: String,
}
