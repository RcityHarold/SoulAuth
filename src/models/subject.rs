use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, SurrealValue)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    Human,
    Agent,
}

impl SubjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SubjectType::Human => "human",
            SubjectType::Agent => "agent",
        }
    }
}

impl Default for SubjectType {
    fn default() -> Self {
        SubjectType::Human
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct Subject {
    pub id: Option<Thing>,
    pub subject_type: String,
    pub created_at: i64,
    pub updated_at: i64,
}
