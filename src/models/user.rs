use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId as Thing;
use surrealdb::types::SurrealValue;

fn default_membership_level() -> String {
    "FREE".to_string()
}

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
    /// 验证令牌的过期时间（Unix 秒）。以前的验证令牌永不过期。
    #[serde(default)]
    pub verification_token_expires_at: Option<i64>,
    pub account_status: String,
    #[serde(default = "default_membership_level")]
    pub membership_level: String,
    #[serde(default)]
    pub membership_expiry: Option<String>,
    pub last_login_at: Option<i64>,
    pub last_login_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, SurrealValue)]
pub enum AccountStatus {
    Active,
    Inactive,
    Suspended,
    PendingDeletion,
    Deleted,
}

impl AccountStatus {
    /// 由库中存的字符串还原状态。
    ///
    /// **未知值一律落到 `Inactive`（不可用）**，而不是 `Active`。以前三处调用点
    /// 各写各的 match，且都以「没被列为坏的就算好的」收尾；只要 `AccountStatus`
    /// 新增一个变体而漏改其中一处，那处就静默放行 —— 没有任何编译错误或运行时
    /// 报错会提示这件事。放行的集合必须是闭的，且只能有一份。
    pub fn parse(raw: &str) -> Self {
        match raw {
            "Active" => AccountStatus::Active,
            "Inactive" => AccountStatus::Inactive,
            "Suspended" => AccountStatus::Suspended,
            "PendingDeletion" => AccountStatus::PendingDeletion,
            "Deleted" => AccountStatus::Deleted,
            _ => AccountStatus::Inactive,
        }
    }

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
    #[serde(default)]
    pub is_admin: bool,
    #[serde(rename = "verified")]
    pub is_email_verified: bool,
    pub membership_level: String,
    pub membership_expiry: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMembershipRequest {
    pub membership_level: String,
    pub membership_expiry: Option<String>,
}

impl User {
    /// 账号是否处于可用状态。鉴权闸门与登录闸门都走这里，不各写各的。
    pub fn account_status_parsed(&self) -> AccountStatus {
        AccountStatus::parse(&self.account_status)
    }
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        let account_status = AccountStatus::parse(&user.account_status);

        let created_at = DateTime::<Utc>::from_timestamp(user.created_at, 0)
            .unwrap_or_else(Utc::now);
        let last_login_at = user
            .last_login_at
            .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0));

        Self {
            // `id` 是 Option（新建时还没有），这里用 unwrap 会把一条缺 id 的记录
            // 变成整个 handler 线程 panic。降级成空串，交由上层按“找不到用户”处理。
            id: user
                .id
                .as_ref()
                .map(crate::utils::record_id::record_id_key_to_string)
                .unwrap_or_default(),
            email: user.email,
            username: user.username,
            is_admin: false,
            is_email_verified: user.is_email_verified,
            membership_level: user.membership_level,
            membership_expiry: user.membership_expiry,
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

#[cfg(test)]
mod account_status_tests {
    use super::AccountStatus;

    #[test]
    fn an_unknown_status_is_not_usable() {
        // 这是本文件最重要的一条：未知值必须落到不可用。
        // 反过来（未知 → Active）意味着任何一次拼写错误、数据迁移遗漏或
        // 新增变体漏改，都会变成一个不报错的放行漏洞。
        for raw in ["", "active", "ACTIVE", "Locked", "Banned", "已停用"] {
            assert_ne!(
                AccountStatus::parse(raw),
                AccountStatus::Active,
                "{raw:?} must not be treated as an active account"
            );
        }
    }

    #[test]
    fn only_active_maps_to_active() {
        assert_eq!(AccountStatus::parse("Active"), AccountStatus::Active);
        for raw in ["Inactive", "Suspended", "PendingDeletion", "Deleted"] {
            assert_ne!(AccountStatus::parse(raw), AccountStatus::Active, "{raw}");
        }
    }

    #[test]
    fn parse_round_trips_every_variant() {
        // as_str 与 parse 必须互逆。任一侧漏掉一个变体，这条就会红 ——
        // 而漏掉的那个变体在 parse 里会落进未知分支，变成永久不可用。
        for v in [
            AccountStatus::Active,
            AccountStatus::Inactive,
            AccountStatus::Suspended,
            AccountStatus::PendingDeletion,
            AccountStatus::Deleted,
        ] {
            assert_eq!(AccountStatus::parse(v.as_str()), v, "{} did not round-trip", v.as_str());
        }
    }
}
