use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct SocialGroup {
    pub id: Option<Thing>,
    pub name: String,
    pub avatar: String,
    #[serde(rename = "type")]
    pub group_type: u8,
    pub level: String,
    #[serde(rename = "ownerId")]
    pub owner_id: String,
    pub created_at: String,
    #[serde(default)]
    pub admin_ids: Vec<String>,
    #[serde(default)]
    pub member_ids: Vec<String>,
    pub announcement: Option<String>,
    pub settings: Option<GroupSettings>,
    pub code: Option<String>,
    #[serde(default)]
    pub human_member_ids: Vec<String>,
    #[serde(default)]
    pub ai_member_ids: Vec<String>,
    pub description: Option<String>,
    pub max_humans: Option<usize>,
    pub max_ais: Option<usize>,
    #[serde(default)]
    pub member_user_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct GroupSettings {
    #[serde(default = "default_join_mode")]
    pub join_mode: String,
    #[serde(default = "default_true")]
    pub allow_member_invite: bool,
    #[serde(default = "default_true")]
    pub allow_file_upload: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: u8,
    pub level: Option<String>,
    #[serde(default)]
    pub member_ids: Vec<String>,
    #[serde(default)]
    pub human_member_ids: Vec<String>,
    #[serde(default)]
    pub ai_member_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddGroupMembersRequest {
    #[serde(default)]
    pub member_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateGroupSettingsRequest {
    pub allow_member_invite: bool,
    pub join_mode: String,
    pub allow_file_upload: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateGroupAnnouncementRequest {
    pub announcement: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateGroupAdminRequest {
    pub target_user_id: String,
    pub is_admin: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferGroupOwnershipRequest {
    pub new_owner_id: String,
}

fn default_true() -> bool {
    true
}

fn default_join_mode() -> String {
    "ADMIN_APPROVAL".to_string()
}
