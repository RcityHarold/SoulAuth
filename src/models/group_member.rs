use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SocialGroupMember {
    pub id: Option<Thing>,
    pub group_id: String,
    pub member_id: String,
    pub member_kind: String,
    pub created_at: String,
}
