use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

#[derive(Debug, Serialize, Deserialize, Clone, SurrealValue)]
pub struct User {
    pub id: Option<Thing>,
    pub subject_id: Option<Thing>,
    pub email: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub username_normalized: String,
    #[surreal(rename = "password")]
    #[serde(rename = "password")]
    pub password_hash: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    #[surreal(rename = "verified")]
    #[serde(rename = "verified")]
    pub is_email_verified: bool,
    pub verification_token: Option<String>,
    pub account_status: String,
    pub last_login_at: Option<i64>,
    pub last_login_ip: Option<String>,
}

#[derive(Debug, Clone, SurrealValue)]
pub enum AccountStatus {
    Active,
    Inactive,
    Suspended,
    PendingDeletion,
    Deleted,
}

impl AccountStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AccountStatus::Active => "Active",
            AccountStatus::Inactive => "Inactive",
            AccountStatus::Suspended => "Suspended",
            AccountStatus::PendingDeletion => "PendingDeletion",
            AccountStatus::Deleted => "Deleted",
        }
    }
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for AccountStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for AccountStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "Active" => Ok(AccountStatus::Active),
            "Inactive" => Ok(AccountStatus::Inactive),
            "Suspended" => Ok(AccountStatus::Suspended),
            "PendingDeletion" => Ok(AccountStatus::PendingDeletion),
            "Deleted" => Ok(AccountStatus::Deleted),
            other => Err(serde::de::Error::custom(format!(
                "invalid account status: {other}"
            ))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub username: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub username: String,
    #[serde(rename = "verified")]
    pub is_email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub has_password: bool,
    pub account_status: AccountStatus,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializePasswordRequest {
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateAccountStatusRequest {
    pub status: AccountStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountStatusResponse {
    pub user_id: String,
    pub status: AccountStatus,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserListRequest {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub status: Option<AccountStatus>,
    pub search: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserListResponse {
    pub users: Vec<UserResponse>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
    pub total_pages: u32,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        let account_status = match user.account_status.as_str() {
            "Active" => AccountStatus::Active,
            "Inactive" => AccountStatus::Inactive,
            "Suspended" => AccountStatus::Suspended,
            "PendingDeletion" => AccountStatus::PendingDeletion,
            "Deleted" => AccountStatus::Deleted,
            _ => AccountStatus::Active,
        };

        let created_at = DateTime::<Utc>::from_timestamp(user.created_at, 0)
            .unwrap_or_else(Utc::now);
        let last_login_at = user
            .last_login_at
            .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0));

        Self {
            id: crate::utils::record_id::record_id_key_to_string(&user.id.unwrap()),
            email: user.email,
            username: user.username,
            is_email_verified: user.is_email_verified,
            created_at,
            has_password: user.password_hash.is_some(),
            account_status,
            last_login_at,
        }
    }
}

impl Default for AccountStatus {
    fn default() -> Self {
        AccountStatus::Active
    }
}
