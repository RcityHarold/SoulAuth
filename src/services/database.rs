use std::{env, fmt::Debug};
use std::time::Duration;
use surrealdb::engine::remote::http::{Client, Http};
use surrealdb::opt::auth::Root;
use surrealdb::{Surreal, types::RecordId};
use surrealdb::types::RecordId as Thing;
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
}

impl Database {
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
        msg.contains("401") || msg.contains("Unauthorized")
    }

    async fn fresh_client(&self) -> Result<Surreal<Client>> {
        let endpoint_raw = env::var("DATABASE_URL").unwrap_or_else(|_| "127.0.0.1:8000".to_string());
        let endpoint = endpoint_raw.trim().trim_end_matches('/').to_string();
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

    async fn retry_on_unauthorized<T, F, Fut>(&self, op_name: &str, f: F) -> Result<T>
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
                    warn!("{op_name} failed with 401, reauth and retry once");
                    self.reauth().await?;
                    f().await
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
        let client = tokio::time::timeout(
            Duration::from_secs(config.database_connection_timeout),
            Surreal::<Client>::new::<Http>(&config.database_url)
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
        })
    }

    /// 验证数据库连接
    /// 注意：数据库schema应该通过schema.sql文件手动创建
    pub async fn verify_connection(&self) -> Result<()> {
        self.retry_on_unauthorized("verify_connection", || async {
            // 使用 INFO 查询验证数据库连接
            let query = "INFO FOR DB";
            self.client
                .query(query)
                .await
                .map_err(|e| AuthError::DatabaseError(format!("Database connection failed: {e}")))?;
            Ok(())
        })
        .await?;

        debug!("Database connection verified successfully");
        Ok(())
    }

    pub async fn create_record<T>(&self, table: &str, record: &T) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Debug + SurrealValue + 'static,
    {
        debug!("Creating record in table {}: {:?}", table, record);

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

            match self.retry_on_unauthorized("find_record_by_field(id)", || async {
                let mut result = self
                    .client
                    .query(&query)
                    .bind(("value", rid.clone()))
                    .await
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
                    warn!("find_record_by_field(id) still unauthorized after reauth, retrying on fresh client");
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

            match self.retry_on_unauthorized("find_record_by_field", || async {
                let mut result = self
                    .client
                    .query(&query)
                    .bind(("value", value.to_string()))
                    .await
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
                    warn!("find_record_by_field still unauthorized after reauth, retrying on fresh client");
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

    pub async fn delete_session_by_token(&self, token: &str) -> Result<()> {
        let query = "DELETE session WHERE token = $session_token";
        self.client
            .query(query)
            .bind(("session_token", token.to_owned()))
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to delete session: {}", e)))?;
        Ok(())
    }

    pub async fn delete_sessions_by_user_id(&self, user_id: &str) -> Result<()> {
        let query = "DELETE session WHERE user_id = type::thing($user_id)";
        let user_thing_str = if user_id.starts_with("user:") {
            user_id.to_string()
        } else {
            format!("user:{}", user_id)
        };
        self.client
            .query(query)
            .bind(("user_id", user_thing_str))
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to delete sessions: {}", e)))?;
        Ok(())
    }

    pub async fn get_sessions_by_user_id(&self, user_id: &str) -> Result<Vec<crate::models::session::Session>> {
        let query = "SELECT * FROM session WHERE user_id = type::thing($user_id) ORDER BY created_at DESC";
        let user_thing_str = if user_id.starts_with("user:") {
            user_id.to_string()
        } else {
            format!("user:{}", user_id)
        };
        let mut result = self
            .client
            .query(query)
            .bind(("user_id", user_thing_str))
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to query sessions: {}", e)))?;
        
        let sessions = result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse sessions: {}", e)))?;
            
        Ok(sessions)
    }

    /// 公开的查询方法，供其他服务使用  
    pub fn query<'a>(&'a self, sql: &'a str) -> surrealdb::method::Query<'a, Client> {
        self.client.query(sql)
    }
}
