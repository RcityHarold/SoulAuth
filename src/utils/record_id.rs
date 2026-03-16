use surrealdb::types::{RecordId, RecordIdKey};

pub fn record_id_key_to_string(id: &RecordId) -> String {
    match &id.key {
        RecordIdKey::String(v) => v.clone(),
        RecordIdKey::Number(v) => v.to_string(),
        RecordIdKey::Uuid(v) => v.to_string(),
        // Fallback for composite keys; not used by current auth IDs.
        _ => serde_json::to_string(&id.key).unwrap_or_default(),
    }
}
