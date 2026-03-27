use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: Option<Thing>, 
    pub email: String,
    pub username: String,
    #[serde(default)]
    pub username_normalized: String,
    #[serde(rename = "password")]
    pub password_hash: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
    #[serde(rename = "verified")]
    pub is_email_verified: bool,
    pub verification_token: Option<String>,
    pub account_status: AccountStatus,
    #[serde(with = "chrono::serde::ts_seconds_option")]
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AccountStatus {
    Active,
    Inactive,
    Suspended,
    PendingDeletion,
    Deleted,
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
        Self {
            id: user.id.unwrap().id.to_string(),
            email: user.email,
            username: user.username,
            is_email_verified: user.is_email_verified,
            created_at: user.created_at,
            has_password: user.password_hash.is_some(),
            account_status: user.account_status,
            last_login_at: user.last_login_at,
        }
    }
}

impl Default for AccountStatus {
    fn default() -> Self {
        AccountStatus::Active
    }
}
