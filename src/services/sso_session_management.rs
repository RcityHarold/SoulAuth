use std::sync::Arc;
use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::{
    models::sso_session::{
        SsoSession, ClientSession, CreateSsoSessionRequest, SsoSessionResponse
    },
    services::database::Database,
};

#[derive(Clone)]
pub struct SsoSessionService {
    db: Arc<Database>,
}

impl SsoSessionService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    // 创建 SSO 会话
    pub async fn create_session(
        &self,
        request: CreateSsoSessionRequest,
    ) -> Result<SsoSessionResponse> {
        let now = Utc::now().timestamp();
        let session_id = Uuid::new_v4().to_string();
        let expires_in = request.expires_in.unwrap_or(8 * 3600); // 默认8小时
        let expires_at = now + expires_in;

        // 创建初始客户端会话
        let client_session = ClientSession {
            client_id: request.client_id.clone(),
            session_id: Uuid::new_v4().to_string(),
            created_at: now,
            last_accessed_at: now,
        };

        let sso_session = SsoSession {
            id: None,
            session_id: session_id.clone(),
            user_id: request.user_id.clone(),
            client_sessions: vec![client_session],
            created_at: now,
            last_accessed_at: now,
            expires_at,
            ip_address: request.ip_address.clone(),
            user_agent: request.user_agent.clone(),
        };

        // 保存到数据库
        self.save_session(&sso_session).await?;

        let is_active = !sso_session.is_expired();
        Ok(SsoSessionResponse {
            session_id,
            user_id: sso_session.user_id,
            client_sessions: sso_session.client_sessions,
            created_at: sso_session.created_at,
            last_accessed_at: sso_session.last_accessed_at,
            expires_at: sso_session.expires_at,
            is_active,
        })
    }

    /// `sso_session.user_id` 在库里是 `record<user>`，而模型侧是字符串，
    /// 因此所有读取都要显式投影一次。
    const SESSION_PROJECTION: &'static str = "type::string(id) AS id, session_id, \
         type::string(user_id) AS user_id, client_sessions, created_at, \
         last_accessed_at, expires_at, ip_address, user_agent";

    // 获取 SSO 会话
    pub async fn get_session(&self, session_id: &str) -> Result<SsoSession> {
        let query = format!(
            "SELECT {} FROM sso_session WHERE session_id = $session_id LIMIT 1",
            Self::SESSION_PROJECTION
        );

        let rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "sso_get_session",
                &query,
                serde_json::json!({ "session_id": session_id }),
            )
            .await?;

        rows.into_iter()
            .next()
            .map(serde_json::from_value::<SsoSession>)
            .transpose()?
            .ok_or_else(|| anyhow!("Session not found"))
    }

    // 添加客户端会话
    pub async fn add_client_session(
        &self,
        session_id: &str,
        client_id: &str,
    ) -> Result<SsoSessionResponse> {
        let mut session = self.get_session(session_id).await?;

        if session.is_expired() {
            return Err(anyhow!("Session has expired"));
        }

        // 添加客户端会话
        session.add_client_session(client_id.to_string());

        // 更新数据库
        self.update_session(&session).await?;

        let is_active = !session.is_expired();
        Ok(SsoSessionResponse {
            session_id: session.session_id,
            user_id: session.user_id,
            client_sessions: session.client_sessions,
            created_at: session.created_at,
            last_accessed_at: session.last_accessed_at,
            expires_at: session.expires_at,
            is_active,
        })
    }

    // 移除客户端会话（单点登出）
    pub async fn remove_client_session(
        &self,
        session_id: &str,
        client_id: &str,
    ) -> Result<SsoSessionResponse> {
        let mut session = self.get_session(session_id).await?;

        // 移除客户端会话
        session.remove_client_session(client_id);

        // 如果没有活跃的客户端会话，删除整个 SSO 会话
        if session.client_sessions.is_empty() {
            self.delete_session(session_id).await?;
        } else {
            self.update_session(&session).await?;
        }

        let is_expired = session.is_expired();
        let client_sessions_empty = session.client_sessions.is_empty();
        Ok(SsoSessionResponse {
            session_id: session.session_id,
            user_id: session.user_id,
            client_sessions: session.client_sessions,
            created_at: session.created_at,
            last_accessed_at: session.last_accessed_at,
            expires_at: session.expires_at,
            is_active: !is_expired && !client_sessions_empty,
        })
    }

    /// 读取某用户全部未过期的 SSO 会话。
    ///
    /// `expires_at` 是 Unix 秒（`TYPE number`），所以必须和一个数字比较 ——
    /// 原来写的是 `expires_at > time::now()`，拿 number 跟 datetime 比，
    /// 过滤条件根本不成立。
    async fn load_user_sessions(&self, user_id: &str) -> Result<Vec<SsoSession>> {
        let query = format!(
            "SELECT {} FROM sso_session \
             WHERE user_id = type::record('user', $user_key) AND expires_at > $now \
             ORDER BY last_accessed_at DESC",
            Self::SESSION_PROJECTION
        );

        let rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "sso_load_user_sessions",
                &query,
                serde_json::json!({
                    "user_key": crate::utils::record_id::normalize_user_id(user_id),
                    "now": Utc::now().timestamp(),
                }),
            )
            .await?;

        let sessions = rows
            .into_iter()
            .map(serde_json::from_value::<SsoSession>)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(sessions.into_iter().filter(|s| !s.is_expired()).collect())
    }

    // 获取用户的所有活跃会话
    pub async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SsoSessionResponse>> {
        Ok(self
            .load_user_sessions(user_id)
            .await?
            .into_iter()
            .map(|s| {
                let is_active = !s.is_expired();
                SsoSessionResponse {
                    session_id: s.session_id,
                    user_id: s.user_id,
                    client_sessions: s.client_sessions,
                    created_at: s.created_at,
                    last_accessed_at: s.last_accessed_at,
                    expires_at: s.expires_at,
                    is_active,
                }
            })
            .collect())
    }

    // 终止用户的所有 SSO 会话
    pub async fn logout_user_all_sessions(&self, user_id: &str) -> Result<i32> {
        // 先数一遍再删，返回真实条数 —— 以前这里无条件返回 1。
        let terminated = self.load_user_sessions(user_id).await?.len() as i32;

        self.db
            .raw_query(
                "sso_logout_user_all_sessions",
                "DELETE sso_session WHERE user_id = type::record('user', $user_key)",
                serde_json::json!({
                    "user_key": crate::utils::record_id::normalize_user_id(user_id),
                }),
            )
            .await?;

        Ok(terminated)
    }

    // 终止特定 SSO 会话
    pub async fn logout_session(&self, session_id: &str) -> Result<()> {
        self.delete_session(session_id).await
    }

    // 清理过期会话
    pub async fn cleanup_expired_sessions(&self) -> Result<i32> {
        // expires_at 是 Unix 秒，不能拿它跟 time::now() 的 datetime 比。
        let now = Utc::now().timestamp();
        let expired = self.count_sessions("expires_at < $now", Some(now)).await?;

        self.db
            .raw_query(
                "sso_cleanup_expired_sessions",
                "DELETE sso_session WHERE expires_at < $now",
                serde_json::json!({ "now": now }),
            )
            .await?;

        Ok(expired as i32)
    }

    async fn count_sessions(&self, predicate: &str, now: Option<i64>) -> Result<i64> {
        let query = if predicate.is_empty() {
            "SELECT count() AS count FROM sso_session GROUP ALL".to_string()
        } else {
            format!("SELECT count() AS count FROM sso_session WHERE {predicate} GROUP ALL")
        };

        let rows: Vec<serde_json::Value> = self
            .db
            .query_take0_vec(
                "sso_count_sessions",
                &query,
                serde_json::json!({ "now": now.unwrap_or(0) }),
            )
            .await?;

        Ok(rows
            .first()
            .and_then(|row| row.get("count"))
            .and_then(|count| count.as_i64())
            .unwrap_or(0))
    }

    // 延长会话过期时间
    pub async fn extend_session(
        &self,
        session_id: &str,
        extend_seconds: i64,
    ) -> Result<SsoSessionResponse> {
        let mut session = self.get_session(session_id).await?;

        if session.is_expired() {
            return Err(anyhow!("Cannot extend expired session"));
        }

        let now = Utc::now().timestamp();
        session.expires_at = now + extend_seconds;
        session.last_accessed_at = now;

        self.update_session(&session).await?;

        let is_active = !session.is_expired();
        Ok(SsoSessionResponse {
            session_id: session.session_id,
            user_id: session.user_id,
            client_sessions: session.client_sessions,
            created_at: session.created_at,
            last_accessed_at: session.last_accessed_at,
            expires_at: session.expires_at,
            is_active,
        })
    }

    // 私有方法：保存会话到数据库
    async fn save_session(&self, session: &SsoSession) -> Result<()> {
        let query = r#"
            CREATE sso_session CONTENT {
                session_id: $session_id,
                user_id: type::record('user', $user_key),
                client_sessions: $client_sessions,
                created_at: $created_at,
                last_accessed_at: $last_accessed_at,
                expires_at: $expires_at,
                ip_address: $ip_address,
                user_agent: $user_agent
            }
        "#;

        self.db.client
            .query(query)
            .bind(("session_id", session.session_id.clone()))
            .bind((
                "user_key",
                crate::utils::record_id::normalize_user_id(&session.user_id),
            ))
            .bind(("client_sessions", session.client_sessions.clone()))
            .bind(("created_at", session.created_at))
            .bind(("last_accessed_at", session.last_accessed_at))
            .bind(("expires_at", session.expires_at))
            .bind(("ip_address", session.ip_address.clone()))
            .bind(("user_agent", session.user_agent.clone()))
            .await?;

        Ok(())
    }

    // 私有方法：更新会话
    async fn update_session(&self, session: &SsoSession) -> Result<()> {
        let query = r#"
            UPDATE sso_session SET
                client_sessions = $client_sessions,
                last_accessed_at = $last_accessed_at,
                expires_at = $expires_at
            WHERE session_id = $session_id
        "#;

        self.db.client
            .query(query)
            .bind(("session_id", session.session_id.clone()))
            .bind(("client_sessions", session.client_sessions.clone()))
            .bind(("last_accessed_at", session.last_accessed_at))
            .bind(("expires_at", session.expires_at))
            .await?;

        Ok(())
    }

    // 私有方法：删除会话
    async fn delete_session(&self, session_id: &str) -> Result<()> {
        let query = "DELETE FROM sso_session WHERE session_id = $session_id";
        
        self.db.client
            .query(query)
            .bind(("session_id", session_id.to_owned()))
            .await?;

        Ok(())
    }
}

// 会话统计服务
impl SsoSessionService {
    // 获取活跃会话统计
    pub async fn get_session_stats(&self) -> Result<SessionStats> {
        let now = Utc::now().timestamp();
        let total_sessions = self.count_sessions("", None).await?;
        let active_sessions = self.count_sessions("expires_at > $now", Some(now)).await?;

        Ok(SessionStats {
            total_sessions,
            active_sessions,
            expired_sessions: (total_sessions - active_sessions).max(0),
        })
    }

    // 获取用户会话统计
    pub async fn get_user_session_stats(&self, user_id: &str) -> Result<UserSessionStats> {
        let sessions = self.get_user_sessions(user_id).await?;
        let total_clients: std::collections::HashSet<String> = sessions
            .iter()
            .flat_map(|s| s.client_sessions.iter().map(|cs| cs.client_id.clone()))
            .collect();

        Ok(UserSessionStats {
            total_sessions: sessions.len() as i32,
            active_clients: total_clients.len() as i32,
            last_activity: sessions.first().map(|s| s.last_accessed_at),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SessionStats {
    pub total_sessions: i64,
    pub active_sessions: i64,
    pub expired_sessions: i64,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct UserSessionStats {
    pub total_sessions: i32,
    pub active_clients: i32,
    pub last_activity: Option<i64>,
}
