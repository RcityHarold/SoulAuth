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

pub fn normalize_record_id_key(value: &str) -> String {
    let mut normalized = value.trim().to_string();

    loop {
        let next = normalized
            .trim()
            .trim_matches('⟨')
            .trim_matches('⟩')
            .trim_matches('<')
            .trim_matches('>')
            .trim_matches('"')
            .trim_matches('`')
            .trim()
            .to_string();

        if next == normalized {
            return next;
        }

        normalized = next;
    }
}

pub fn normalize_user_id(value: &str) -> String {
    let mut normalized = normalize_record_id_key(value);

    loop {
        let next = if let Some(key) = normalized.strip_prefix("user:") {
            normalize_record_id_key(key)
        } else {
            normalize_record_id_key(&normalized)
        };

        if next == normalized {
            return next;
        }

        normalized = next;
    }
}

pub fn user_record_id(value: &str) -> RecordId {
    RecordId::new("user", normalize_user_id(value))
}

#[cfg(test)]
mod tests {
    use super::normalize_user_id;

    #[test]
    fn normalize_user_id_cases() {
        let cases = [
            ("abc", "abc"),
            ("user:abc", "abc"),
            ("user:user:abc", "abc"),
            ("user:\"abc\"", "abc"),
            ("user:`abc`", "abc"),
            ("user:⟨abc⟩", "abc"),
        ];

        for (input, expected) in cases {
            assert_eq!(normalize_user_id(input), expected, "input={input}");
        }
    }
}
