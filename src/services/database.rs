use std::{
    env,
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use std::time::Duration;
use serde_json::Value as JsonValue;
use surrealdb::engine::remote::http::{Client, Http};
use surrealdb::opt::auth::Root;
use surrealdb::{Surreal, types::RecordId};
use surrealdb::types::SurrealValue;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::{config::Config, error::{Result, AuthError}};

#[derive(Clone)]
pub struct Database {
    pub client: Surreal<Client>,
    // Keep auth context so we can re-authenticate when tokens expire.
    database_user: String,
    database_pass: String,
    database_namespace: String,
    database_name: String,
    prefer_fresh_until_epoch: Arc<AtomicU64>,
}

impl Database {
    fn unix_now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    fn should_prefer_fresh(&self) -> bool {
        Self::unix_now_secs() < self.prefer_fresh_until_epoch.load(Ordering::Relaxed)
    }

    fn mark_prefer_fresh_for(&self, seconds: u64) {
        self.prefer_fresh_until_epoch
            .store(Self::unix_now_secs() + seconds, Ordering::Relaxed);
    }

    /// surrealdb 的 `Http` 连接器只接受 `host:port`，带上 `http://` 会被当成
    /// 主机名解析（报 "DNS resolution failed for http:80"）。而 README 和本文件
    /// 里的默认值一直写的是 `http://localhost:8000` —— 也就是照文档配置反而起不来。
    /// 这里统一剥掉 scheme，两种写法都能用。
    fn endpoint_without_scheme(raw: &str) -> String {
        let ep = raw.trim().trim_end_matches('/');
        ep.strip_prefix("http://")
            .or_else(|| ep.strip_prefix("https://"))
            .unwrap_or(ep)
            .to_string()
    }

    fn endpoint_with_scheme(raw: &str) -> String {
        let ep = raw.trim().trim_end_matches('/');
        if ep.starts_with("http://") || ep.starts_with("https://") {
            ep.to_string()
        } else {
            format!("http://{}", ep)
        }
    }

    async fn rpc_signin_token(endpoint: &str, user: &str, pass: &str, ns: &str, db: &str) -> Result<String> {
        let endpoint = endpoint.trim_end_matches('/');
        let rpc_url = format!("{endpoint}/rpc");
        let payloads = [
            serde_json::json!({
                "id": 1,
                "method": "signin",
                "params": [{ "user": user, "pass": pass }]
            }),
            serde_json::json!({
                "id": 1,
                "method": "signin",
                "params": [{ "user": user, "pass": pass, "ns": ns, "db": db }]
            }),
        ];

        let mut last_error = String::new();
        for payload in payloads {
            let resp = reqwest::Client::new()
                .post(&rpc_url)
                .header("Content-Type", "application/json")
                .body(payload.to_string())
                .send()
                .await
                .map_err(|e| AuthError::DatabaseError(format!("RPC signin request failed: {e}")))?;

            let body = resp
                .text()
                .await
                .map_err(|e| AuthError::DatabaseError(format!("RPC signin response read failed: {e}")))?;

            let v: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| AuthError::DatabaseError(format!("RPC signin invalid json: {e}; body={body}")))?;

            if let Some(token) = v.get("result").and_then(|x| x.as_str()) {
                return Ok(token.to_string());
            }
            if let Some(token) = v
                .get("result")
                .and_then(|x| x.get("access"))
                .and_then(|x| x.as_str())
            {
                return Ok(token.to_string());
            }

            last_error = v
                .get("error")
                .cloned()
                .unwrap_or(serde_json::Value::String(body))
                .to_string();
        }

        Err(AuthError::DatabaseError(format!(
            "Failed to authenticate: {}",
            last_error
        )))
    }

    fn is_unauthorized_error<E: std::fmt::Display>(err: &E) -> bool {
        let msg = err.to_string();
        msg.contains("401")
            || msg.contains("Unauthorized")
            || msg.contains("Failed to authenticate")
            || msg.contains("native signin failed")
            || msg.contains("rpc authenticate(token) failed")
            || msg.contains("rpc signin failed")
    }

    fn should_retry_verify_with_fresh<E: std::fmt::Display>(err: &E) -> bool {
        Self::is_unauthorized_error(err)
    }

    pub async fn fresh_client(&self) -> Result<Surreal<Client>> {
        let endpoint_raw = env::var("DATABASE_URL").unwrap_or_else(|_| "127.0.0.1:8000".to_string());
        let endpoint = Self::endpoint_without_scheme(&endpoint_raw);
        let with_scheme = Self::endpoint_with_scheme(&endpoint_raw);
        let ns = self.database_namespace.trim().to_string();
        let db = self.database_name.trim().to_string();
        let user = self.database_user.trim().to_string();
        let pass = self.database_pass.trim().to_string();

        let client = Surreal::<Client>::new::<Http>(&endpoint)
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to connect fresh client: {e}")))?;

        match client
            .signin(Root {
                username: user.clone(),
                password: pass.clone(),
            })
            .await
        {
            Ok(_) => {}
            Err(native_err) => {
                warn!(
                    "fresh client native signin failed for user={} ns={} db={}, fallback to rpc token auth: {}",
                    user, ns, db, native_err
                );
                let token = Self::rpc_signin_token(&with_scheme, &user, &pass, &ns, &db).await?;
                client.authenticate(token).await.map_err(|e| {
                    AuthError::DatabaseError(format!(
                        "Failed to authenticate fresh client: {e}"
                    ))
                })?;
            }
        }

        client
            .use_ns(&ns)
            .use_db(&db)
            .await
            .map_err(|e| {
                AuthError::DatabaseError(format!(
                    "Failed to select namespace/database for fresh client: {e}"
                ))
            })?;

        Ok(client)
    }

    pub async fn reauth(&self) -> Result<()> {
        debug!("Re-authenticating with database (refresh token)");
        let stored_user = self.database_user.trim().to_string();
        let stored_pass = self.database_pass.trim().to_string();
        let stored_ns = self.database_namespace.trim().to_string();
        let stored_db = self.database_name.trim().to_string();

        let env_db_user = env::var("DATABASE_USER").ok().map(|v| v.trim().to_string());
        let env_db_pass = env::var("DATABASE_PASS").ok().map(|v| v.trim().to_string());
        let env_db_ns = env::var("DATABASE_NAMESPACE").ok().map(|v| v.trim().to_string());
        let env_db_name = env::var("DATABASE_NAME").ok().map(|v| v.trim().to_string());

        let env_sur_user = env::var("SURREAL_USER").ok().map(|v| v.trim().to_string());
        let env_sur_pass = env::var("SURREAL_PASS").ok().map(|v| v.trim().to_string());
        let env_sur_ns = env::var("SURREAL_NAMESPACE").ok().map(|v| v.trim().to_string());
        let env_sur_db = env::var("SURREAL_DATABASE").ok().map(|v| v.trim().to_string());

        let mut candidates: Vec<(String, String, String, String)> = Vec::new();
        candidates.push((
            stored_user.clone(),
            stored_pass.clone(),
            stored_ns.clone(),
            stored_db.clone(),
        ));
        if let (Some(u), Some(p)) = (env_db_user.clone(), env_db_pass.clone()) {
            let ns = env_db_ns.clone().unwrap_or_else(|| stored_ns.clone());
            let db = env_db_name.clone().unwrap_or_else(|| stored_db.clone());
            candidates.push((u, p, ns, db));
        }
        if let (Some(u), Some(p)) = (env_sur_user.clone(), env_sur_pass.clone()) {
            let ns = env_sur_ns.clone().unwrap_or_else(|| stored_ns.clone());
            let db = env_sur_db.clone().unwrap_or_else(|| stored_db.clone());
            candidates.push((u, p, ns, db));
        }

        let mut last_err: Option<AuthError> = None;
        for (user, pass, ns, db) in candidates.into_iter() {
            if user.is_empty() || pass.is_empty() || ns.is_empty() || db.is_empty() {
                continue;
            }
            // Prefer native signin first (more stable on SurrealDB 3.x)
            let signin_result = match self
                .client
                .signin(Root {
                    username: user.clone(),
                    password: pass.clone(),
                })
                .await
            {
                Ok(_) => Ok(()),
                Err(native_err) => {
                    warn!(
                        "native signin failed for user={} ns={} db={}, fallback to rpc token auth: {}",
                        user, ns, db, native_err
                    );
                    let endpoint = Self::endpoint_with_scheme(
                        &env::var("DATABASE_URL").unwrap_or_else(|_| "127.0.0.1:8000".to_string()),
                    );
                    match Self::rpc_signin_token(&endpoint, &user, &pass, &ns, &db).await {
                        Ok(token) => self
                            .client
                            .authenticate(token)
                            .await
                            .map(|_| ())
                            .map_err(|auth_err| {
                                AuthError::DatabaseError(format!(
                                    "native signin failed: {native_err}; rpc authenticate(token) failed: {auth_err}"
                                ))
                            }),
                        Err(rpc_err) => Err(AuthError::DatabaseError(format!(
                            "native signin failed: {native_err}; rpc signin failed: {rpc_err}"
                        ))),
                    }
                }
            };
            match signin_result {
                Ok(_) => {
                    self.client
                        .use_ns(&ns)
                        .use_db(&db)
                        .await
                        .map_err(|e| {
                            AuthError::DatabaseError(format!(
                                "Failed to select namespace/database after reauth: {e}"
                            ))
                        })?;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        "Reauth attempt failed for user={} ns={} db={} (will try next if any): {}",
                        user, ns, db, e
                    );
                    last_err = Some(AuthError::DatabaseError(format!(
                        "Failed to authenticate: {e}"
                    )));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            AuthError::DatabaseError("Failed to authenticate: no valid credential candidate".into())
        }))
    }

    pub async fn retry_on_unauthorized<T, F, Fut>(&self, op_name: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        match f().await {
            Ok(v) => Ok(v),
            Err(e) => {
                // SurrealDB may return 401 when the auth token expires.
                let msg = format!("{e}");
                if msg.contains("401") || msg.contains("Unauthorized") {
                    self.mark_prefer_fresh_for(300);
                    warn!("{op_name} failed with 401; caller should retry on fresh client");
                    Err(e)
                } else {
                    Err(e)
                }
            }
        }
    }

    pub async fn new(config: &Config) -> Result<Self> {
        let mut retry_count = 0;
        let max_retries = 5;
        let retry_delay = Duration::from_secs(1);

        loop {
            match Self::try_connect(config).await {
                Ok(db) => return Ok(db),
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        return Err(e);
                    }
                    warn!("Failed to connect to database (attempt {}/{}): {}", retry_count, max_retries, e);
                    sleep(retry_delay).await;
                }
            }
        }
    }

    async fn try_connect(config: &Config) -> Result<Self> {
        debug!("Connecting to database url={}", config.database_url);
        
        // 设置连接超时
        let endpoint = Self::endpoint_without_scheme(&config.database_url);
        let client = tokio::time::timeout(
            Duration::from_secs(config.database_connection_timeout),
            Surreal::<Client>::new::<Http>(&endpoint)
        ).await
        .map_err(|_| AuthError::DatabaseError("Database connection timeout".to_string()))?
        .map_err(|e| AuthError::DatabaseError(format!("Failed to connect: {}", e)))?;
            
        debug!("Authenticating with database");
        // Prefer native signin first, fallback to RPC token authenticate.
        match tokio::time::timeout(
            Duration::from_secs(config.database_connection_timeout),
            client.signin(Root {
                username: config.database_user.clone(),
                password: config.database_pass.clone(),
            }),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(native_err)) => {
                warn!("Database native signin failed at startup, fallback to rpc token auth: {}", native_err);
                let endpoint = Self::endpoint_with_scheme(&config.database_url);
                let token = tokio::time::timeout(
                    Duration::from_secs(config.database_connection_timeout),
                    Self::rpc_signin_token(
                        &endpoint,
                        &config.database_user,
                        &config.database_pass,
                        &config.database_namespace,
                        &config.database_name,
                    ),
                ).await
                .map_err(|_| AuthError::DatabaseError("Database authentication timeout".to_string()))??;
                client
                    .authenticate(token)
                    .await
                    .map_err(|e| AuthError::DatabaseError(format!("Failed to authenticate: {e}")))?;
            }
            Err(_) => {
                return Err(AuthError::DatabaseError("Database authentication timeout".to_string()));
            }
        }
        
        debug!("Selecting namespace and database");
        client.use_ns(&config.database_namespace).use_db(&config.database_name).await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to select namespace/database: {}", e)))?;
        
        debug!("Database connection established successfully");
        Ok(Database {
            client,
            database_user: config.database_user.clone(),
            database_pass: config.database_pass.clone(),
            database_namespace: config.database_namespace.clone(),
            database_name: config.database_name.clone(),
            prefer_fresh_until_epoch: Arc::new(AtomicU64::new(0)),
        })
    }

    /// 验证数据库连接
    /// 注意：数据库schema应该通过schema.sql文件手动创建
    pub async fn verify_connection(&self) -> Result<()> {
        if self.should_prefer_fresh() {
            let fresh = self.fresh_client().await?;
            fresh
                .query("INFO FOR DB")
                .await
                .map_err(|e| AuthError::DatabaseError(format!("Database connection failed: {e}")))?;
            debug!("Database connection verified successfully via fresh client");
            return Ok(());
        }

        match self.retry_on_unauthorized("verify_connection", || async {
            // 使用 INFO 查询验证数据库连接
            let query = "INFO FOR DB";
            self.client
                .query(query)
                .await
                .and_then(|response| response.check())
                .map_err(|e| AuthError::DatabaseError(format!("Database connection failed: {e}")))?;
            Ok(())
        })
        .await
        {
            Ok(()) => {}
            Err(err) if Self::should_retry_verify_with_fresh(&err) => {
                let fresh = self.fresh_client().await?;
                fresh
                    .query("INFO FOR DB")
                    .await
                    .map_err(|e| AuthError::DatabaseError(format!("Database connection failed: {e}")))?;
                debug!("Database connection verified successfully via fresh client after auth refresh");
                return Ok(());
            }
            Err(err) => return Err(err),
        }

        debug!("Database connection verified successfully");
        Ok(())
    }

    pub async fn create_record<T>(&self, table: &str, record: &T) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Debug + SurrealValue + 'static,
    {
        debug!("Creating record in table {}: {:?}", table, record);

        if self.should_prefer_fresh() {
            let fresh = self.fresh_client().await?;
            let created: Option<T> = fresh
                .create(table)
                .content(record.clone())
                .await
                .map_err(|e| AuthError::DatabaseError(format!("Failed to create record: {}", e)))?;
            return created.ok_or_else(|| AuthError::DatabaseError("Failed to create record".into()));
        }

        let created: Option<T> = match self.client.create(table).content(record.clone()).await {
            Ok(created) => created,
            Err(err) if Self::is_unauthorized_error(&err) => {
                warn!("create_record failed with 401, retrying on fresh client");
                let fresh = self.fresh_client().await?;
                fresh.create(table)
                    .content(record.clone())
                    .await
                    .map_err(|e| AuthError::DatabaseError(format!("Failed to create record: {}", e)))?
            }
            Err(err) => {
                return Err(AuthError::DatabaseError(format!("Failed to create record: {}", err)));
            }
        };

        created.ok_or_else(|| AuthError::DatabaseError("Failed to create record".into()))
    }

    pub async fn find_record_by_field<T>(&self, table: &str, field: &str, value: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + Clone + Debug + SurrealValue,
    {
        debug!("Finding record in table {} where {} = {}", table, field, value);

        if field == "id" {
            let (rid_table, rid_key) = if let Some((tb, key_raw)) = value.split_once(':') {
                (
                    tb.to_string(),
                    key_raw.trim().trim_matches('⟨').trim_matches('⟩').to_string(),
                )
            } else {
                (table.to_string(), value.to_string())
            };
            let rid = RecordId::new(rid_table, rid_key);
            let query = format!("SELECT * FROM {} WHERE id = $value", table);
            debug!("执行查询: {}", query);
            debug!("查询参数: value = {:?}", rid);

            if self.should_prefer_fresh() {
                let fresh = self.fresh_client().await?;
                let mut result = fresh
                    .query(&query)
                    .bind(("value", rid))
                    .await
                    .map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to execute id query: {e}"))
                    })?;
                let records: Vec<T> = result
                    .take(0)
                    .map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to parse id records: {e}"))
                    })?;
                return Ok(records.into_iter().next());
            }

            match self.retry_on_unauthorized("find_record_by_field(id)", || async {
                let mut result = self
                    .client
                    .query(&query)
                    .bind(("value", rid.clone()))
                    .await
                    .and_then(|response| response.check())
                    .map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to execute id query: {e}"))
                    })?;

                debug!("原始查询结果: {:?}", result);

                let records: Vec<T> = result
                    .take(0)
                    .map_err(|e| {
                        AuthError::DatabaseError(format!("Failed to parse id records: {e}"))
                    })?;

                debug!("解析后的记录: {:?}", records);
                Ok(records.into_iter().next())
            })
            .await {
                Ok(result) => Ok(result),
                Err(err) if Self::is_unauthorized_error(&err) => {
                    warn!("find_record_by_field(id) retrying on fresh client");
                    let fresh = self.fresh_client().await?;
                    let mut result = fresh
                        .query(&query)
                        .bind(("value", rid))
                        .await
                        .map_err(|e| {
                            AuthError::DatabaseError(format!("Failed to execute id query: {e}"))
                        })?;
                    let records: Vec<T> = result
                        .take(0)
                        .map_err(|e| {
                            AuthError::DatabaseError(format!("Failed to parse id records: {e}"))
                        })?;
                    Ok(records.into_iter().next())
                }
                Err(err) => Err(err),
            }
        } else {
            let query = format!("SELECT * FROM {} WHERE {} = $value", table, field);
            debug!("执行查询: {}", query);
            debug!("查询参数: value = {}", value);

            if self.should_prefer_fresh() {
                let fresh = self.fresh_client().await?;
                let mut result = fresh
                    .query(&query)
                    .bind(("value", value.to_string()))
                    .await
                    .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {e}")))?;
                let records: Vec<T> = result
                    .take(0)
                    .map_err(|e| AuthError::DatabaseError(format!("Failed to parse records: {e}")))?;
                return Ok(records.into_iter().next());
            }

            match self.retry_on_unauthorized("find_record_by_field", || async {
                let mut result = self
                    .client
                    .query(&query)
                    .bind(("value", value.to_string()))
                    .await
                    .and_then(|response| response.check())
                    .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {e}")))?;

                debug!("原始查询结果: {:?}", result);

                let records: Vec<T> = result
                    .take(0)
                    .map_err(|e| AuthError::DatabaseError(format!("Failed to parse records: {e}")))?;

                debug!("解析后的记录: {:?}", records);
                Ok(records.into_iter().next())
            })
            .await {
                Ok(result) => Ok(result),
                Err(err) if Self::is_unauthorized_error(&err) => {
                    warn!("find_record_by_field retrying on fresh client");
                    let fresh = self.fresh_client().await?;
                    let mut result = fresh
                        .query(&query)
                        .bind(("value", value.to_string()))
                        .await
                        .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {e}")))?;
                    let records: Vec<T> = result
                        .take(0)
                        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse records: {e}")))?;
                    Ok(records.into_iter().next())
                }
                Err(err) => Err(err),
            }
        }
    }

    pub async fn update_record<T>(&self, table: &str, id: &str, record: &T) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Debug + SurrealValue + 'static,
    {
        debug!(
            "Updating record in table {} with id {}: {:?}",
            table, id, record
        );

        if self.should_prefer_fresh() {
            let fresh = self.fresh_client().await?;
            let updated = if let Some((tb, key_raw)) = id.split_once(':') {
                let key = key_raw.trim().trim_matches('⟨').trim_matches('⟩');
                let rid = RecordId::new(tb, key);
                fresh.update(rid).content(record.clone()).await
            } else {
                let rid = RecordId::new(table, id);
                fresh.update(rid).content(record.clone()).await
            }
            .map_err(|e| AuthError::DatabaseError(format!("Failed to update record: {}", e)))?;

            return updated.ok_or_else(|| AuthError::DatabaseError("Record not found".into()));
        }

        let updated = match if let Some((tb, key_raw)) = id.split_once(':') {
            let key = key_raw.trim().trim_matches('⟨').trim_matches('⟩');
            let rid = RecordId::new(tb, key);
            self.client.update(rid).content(record.clone()).await
        } else {
            let rid = RecordId::new(table, id);
            self.client.update(rid).content(record.clone()).await
        } {
            Ok(updated) => updated,
            Err(err) if Self::is_unauthorized_error(&err) => {
                warn!("update_record failed with 401, retrying on fresh client");
                let fresh = self.fresh_client().await?;
                if let Some((tb, key_raw)) = id.split_once(':') {
                    let key = key_raw.trim().trim_matches('⟨').trim_matches('⟩');
                    let rid = RecordId::new(tb, key);
                    fresh.update(rid).content(record.clone()).await
                } else {
                    let rid = RecordId::new(table, id);
                    fresh.update(rid).content(record.clone()).await
                }
                .map_err(|e| AuthError::DatabaseError(format!("Failed to update record: {}", e)))?
            }
            Err(err) => {
                return Err(AuthError::DatabaseError(format!("Failed to update record: {}", err)));
            }
        };

        updated.ok_or_else(|| AuthError::DatabaseError("Record not found".into()))
    }


    pub async fn delete_record<T>(&self, table: &str, id: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + Clone + Debug + SurrealValue,
    {
        debug!("Deleting record from table {} with id {}", table, id);
        
        let rid = RecordId::new(table, id);
        let deleted = self
            .client
            .delete(rid)
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to delete record: {}", e)))?;

        Ok(deleted)
    }

    /// 删除单条会话（登出）。
    ///
    /// 走 `raw_query` 而不是直接用 `self.client`：前者会 `.check()` 语句级错误、
    /// 并在鉴权态过期时换新连接重试。以前这里是裸调用，写失败会被吞掉 ——
    /// 登出接口照样返回成功，`session` 行却还在，令牌一直有效到自然过期。
    /// 下面两个同族函数本来就是这么写的，唯独这个漏了。
    pub async fn delete_session_by_token(&self, token: &str) -> Result<()> {
        self.raw_query(
            "delete_session_by_token",
            "DELETE session WHERE token = $session_token",
            serde_json::json!({ "session_token": token }),
        )
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to delete session: {}", e)))?;
        Ok(())
    }

    /// 删除某用户的全部会话（全端登出、改密后强制下线）。
    ///
    /// 必须用 `type::record(table, id)` 两参形式：单参形式会把
    /// `"user:e81b4aa8-05f6-..."` 在第一个连字符处截断成 `user:e81b4aa8`，
    /// 于是条件永远匹配不到任何行 —— 全端登出和改密下线都会变成空操作。
    pub async fn delete_sessions_by_user_id(&self, user_id: &str) -> Result<()> {
        self.raw_query(
            "delete_sessions_by_user_id",
            "DELETE session WHERE user_id = type::record('user', $user_key)",
            serde_json::json!({
                "user_key": crate::utils::record_id::normalize_user_id(user_id),
            }),
        )
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to delete sessions: {}", e)))?;
        Ok(())
    }

    /// 列出某用户的全部会话。两参形式的原因同 `delete_sessions_by_user_id`。
    pub async fn get_sessions_by_user_id(&self, user_id: &str) -> Result<Vec<crate::models::session::Session>> {
        let mut result = self
            .raw_query(
                "get_sessions_by_user_id",
                "SELECT * FROM session WHERE user_id = type::record('user', $user_key) \
                 ORDER BY created_at DESC",
                serde_json::json!({
                    "user_key": crate::utils::record_id::normalize_user_id(user_id),
                }),
            )
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to query sessions: {}", e)))?;

        result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse sessions: {}", e)))
    }

    pub async fn raw_query(
        &self,
        op: &str,
        sql: &str,
        bindings: JsonValue,
    ) -> Result<surrealdb::IndexedResults> {
        if self.should_prefer_fresh() {
            let fresh = self.fresh_client().await?;
            return fresh
                .query(sql)
                .bind(bindings)
                .await
                .and_then(|response| response.check())
                .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {e}")));
        }

        let bindings_for_retry = bindings.clone();
        match self
            .retry_on_unauthorized(op, || {
                let bindings = bindings_for_retry.clone();
                async move {
                    self.client
                        .query(sql)
                        .bind(bindings)
                        .await
                        .and_then(|response| response.check())
                        .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {e}")))
                }
            })
            .await
        {
            Ok(response) => Ok(response),
            Err(err) if Self::is_unauthorized_error(&err) => {
                warn!("{op} retrying on fresh client");
                let fresh = self.fresh_client().await?;
                fresh
                    .query(sql)
                    .bind(bindings)
                    .await
                    .and_then(|response| response.check())
                    .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {e}")))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn raw_query_no_bind(
        &self,
        op: &str,
        sql: &str,
    ) -> Result<surrealdb::IndexedResults> {
        self.raw_query(op, sql, JsonValue::Object(Default::default())).await
    }

    pub async fn query_take0_vec<T>(
        &self,
        op: &str,
        sql: &str,
        bindings: JsonValue,
    ) -> Result<Vec<T>>
    where
        T: serde::de::DeserializeOwned + surrealdb_types::SurrealValue,
    {
        let mut response = self.raw_query(op, sql, bindings).await?;
        response
            .take::<Vec<T>>(0usize)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse query result: {e}")))
    }

    pub async fn query_take0_option<T>(
        &self,
        op: &str,
        sql: &str,
        bindings: JsonValue,
    ) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + surrealdb_types::SurrealValue,
    {
        let mut response = self.raw_query(op, sql, bindings).await?;
        response
            .take::<Option<T>>(0usize)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse query result: {e}")))
    }

    pub async fn query_take0_vec_no_bind<T>(
        &self,
        op: &str,
        sql: &str,
    ) -> Result<Vec<T>>
    where
        T: serde::de::DeserializeOwned + surrealdb_types::SurrealValue,
    {
        self.query_take0_vec(op, sql, JsonValue::Object(Default::default()))
            .await
    }

    pub async fn query_take0_option_no_bind<T>(
        &self,
        op: &str,
        sql: &str,
    ) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + surrealdb_types::SurrealValue,
    {
        self.query_take0_option(op, sql, JsonValue::Object(Default::default()))
            .await
    }

    /// 公开的查询构造器，供其他服务使用。
    ///
    /// 注意：这里返回的是**未执行**的构造器，`.check()` 只能由调用方在 `.await`
    /// 之后自己加。需要自动 check + 401 重试的场合请优先用 `raw_query`。
    /// 当前无调用点，保留仅为对外扩展。
    #[allow(dead_code)]
    pub fn query<'a>(&'a self, sql: &'a str) -> surrealdb::method::Query<'a, Client> {
        self.client.query(sql)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_without_scheme_accepts_both_forms() {
        assert_eq!(Database::endpoint_without_scheme("http://localhost:8000"), "localhost:8000");
        assert_eq!(Database::endpoint_without_scheme("https://db.example:8000/"), "db.example:8000");
        assert_eq!(Database::endpoint_without_scheme(" 127.0.0.1:8000 "), "127.0.0.1:8000");
    }

    #[test]
    fn endpoint_with_scheme_adds_http_when_missing() {
        assert_eq!(Database::endpoint_with_scheme("127.0.0.1:8000"), "http://127.0.0.1:8000");
        assert_eq!(Database::endpoint_with_scheme("https://db.example:8000/"), "https://db.example:8000");
    }

    #[test]
    fn verify_connection_retries_with_fresh_client_for_expired_auth() {
        let error = AuthError::DatabaseError(
            "Database connection failed: HTTP status client error (401 Unauthorized)".to_string(),
        );

        assert!(Database::should_retry_verify_with_fresh(&error));
    }
}
