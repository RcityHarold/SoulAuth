use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct UserPreferences {
    pub id: Option<Thing>,
    pub user_id: Thing,
    pub theme: String,
    pub language: String,
    pub email_notifications: bool,
    pub sms_notifications: bool,
    pub marketing_emails: bool,
    pub security_emails: bool,
    pub newsletter: bool,
    pub two_factor_required: bool,
    pub session_timeout: i32,
    pub timezone: String,
    pub date_format: String,
    pub time_format: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserPreferencesRequest {
    pub theme: Option<String>,
    pub language: Option<String>,
    pub email_notifications: Option<bool>,
    pub sms_notifications: Option<bool>,
    pub marketing_emails: Option<bool>,
    pub security_emails: Option<bool>,
    pub newsletter: Option<bool>,
    pub two_factor_required: Option<bool>,
    pub session_timeout: Option<i32>,
    pub timezone: Option<String>,
    pub date_format: Option<String>,
    pub time_format: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserPreferencesRequest {
    pub theme: Option<String>,
    pub language: Option<String>,
    pub email_notifications: Option<bool>,
    pub sms_notifications: Option<bool>,
    pub marketing_emails: Option<bool>,
    pub security_emails: Option<bool>,
    pub newsletter: Option<bool>,
    pub two_factor_required: Option<bool>,
    pub session_timeout: Option<i32>,
    pub timezone: Option<String>,
    pub date_format: Option<String>,
    pub time_format: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPreferencesResponse {
    pub id: String,
    pub user_id: String,
    pub theme: String,
    pub language: String,
    pub email_notifications: bool,
    pub sms_notifications: bool,
    pub marketing_emails: bool,
    pub security_emails: bool,
    pub newsletter: bool,
    pub two_factor_required: bool,
    pub session_timeout: i32,
    pub timezone: String,
    pub date_format: String,
    pub time_format: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserPreferences> for UserPreferencesResponse {
    fn from(prefs: UserPreferences) -> Self {
        Self {
            id: prefs.id
                .map(|id| crate::utils::record_id::record_id_key_to_string(&id))
                .unwrap_or_default(),
            user_id: crate::utils::record_id::record_id_key_to_string(&prefs.user_id),
            theme: prefs.theme,
            language: prefs.language,
            email_notifications: prefs.email_notifications,
            sms_notifications: prefs.sms_notifications,
            marketing_emails: prefs.marketing_emails,
            security_emails: prefs.security_emails,
            newsletter: prefs.newsletter,
            two_factor_required: prefs.two_factor_required,
            session_timeout: prefs.session_timeout,
            timezone: prefs.timezone,
            date_format: prefs.date_format,
            time_format: prefs.time_format,
            created_at: prefs.created_at,
            updated_at: prefs.updated_at,
        }
    }
}

impl Default for UserPreferences {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            id: None,
            user_id: Thing::new("user", "default"),
            theme: "light".to_string(),
            language: "en".to_string(),
            email_notifications: true,
            sms_notifications: false,
            marketing_emails: false,
            security_emails: true,
            newsletter: false,
            two_factor_required: false,
            session_timeout: 86400, // 24 hours
            timezone: "UTC".to_string(),
            date_format: "YYYY-MM-DD".to_string(),
            time_format: "24h".to_string(),
            created_at: now,
            updated_at: now,
        }
    }
}
