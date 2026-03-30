use serde::{Deserialize, Serialize};
use serde_json::Value;
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct GroupCollabRun {
    pub id: Option<Thing>,
    pub group_id: String,
    pub thread_id: String,
    pub scenario_type: u8,
    pub triggered_by: String,
    pub strategy_type: String,
    pub status: String,
    pub prompt: String,
    pub participant_ids: Vec<String>,
    pub metadata: Option<Value>,
    pub result_summary: Option<String>,
    pub result_payload: Option<Value>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupCollabRunRequest {
    pub strategy_type: String,
    pub prompt: String,
    #[serde(default)]
    pub participant_ids: Vec<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompleteGroupCollabRunRequest {
    pub status: String,
    #[serde(default)]
    pub result_summary: Option<String>,
    #[serde(default)]
    pub result_payload: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupCollabRunView {
    pub id: String,
    pub group_id: String,
    pub thread_id: String,
    pub scenario_type: u8,
    pub triggered_by: String,
    pub strategy_type: String,
    pub status: String,
    pub prompt: String,
    pub participant_ids: Vec<String>,
    pub metadata: Option<Value>,
    pub result_summary: Option<String>,
    pub result_payload: Option<Value>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}
