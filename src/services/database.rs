use std::fmt::Debug;
use std::time::Duration;
use surrealdb::engine::remote::http::{Client, Http};
use surrealdb::opt::auth::Root;
use surrealdb::sql::Thing;
use surrealdb::Surreal;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::{config::Config, error::{Result, AuthError}};

#[derive(Clone)]
pub struct Database {
    pub client: Surreal<Client>,
}

impl Database {
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
        debug!("Connecting to database");
        
        // 设置连接超时
        let client = tokio::time::timeout(
            Duration::from_secs(config.database_connection_timeout),
            Surreal::<Client>::new::<Http>(&config.database_url)
        ).await
        .map_err(|_| AuthError::DatabaseError("Database connection timeout".to_string()))?
        .map_err(|e| AuthError::DatabaseError(format!("Failed to connect: {}", e)))?;
            
        debug!("Authenticating with database");
        tokio::time::timeout(
            Duration::from_secs(config.database_connection_timeout),
            client.signin(Root {
                username: &config.database_user,
                password: &config.database_pass,
            })
        ).await
        .map_err(|_| AuthError::DatabaseError("Database authentication timeout".to_string()))?
        .map_err(|e| AuthError::DatabaseError(format!("Failed to authenticate: {}", e)))?;
        
        debug!("Selecting namespace and database");
        client.use_ns(&config.database_namespace).use_db(&config.database_name).await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to select namespace/database: {}", e)))?;
        
        debug!("Database connection established successfully");
        Ok(Database { client })
    }

    /// 验证数据库连接
    /// 注意：数据库schema应该通过schema.sql文件手动创建
    pub async fn verify_connection(&self) -> Result<()> {
        // 使用 INFO 查询验证数据库连接
        let query = "INFO FOR DB";
        self.client.query(query).await
            .map_err(|e| AuthError::DatabaseError(format!("Database connection failed: {}", e)))?;
        
        debug!("Database connection verified successfully");
        Ok(())
    }

    pub async fn create_record<T>(&self, table: &str, record: &T) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Debug + 'static,
    {
        debug!("Creating record in table {}: {:?}", table, record);
        
        let created: Option<T> = self.client
            .create(table)
            .content(record.clone())
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to create record: {}", e)))?;
            
        created
            .ok_or_else(|| AuthError::DatabaseError("Failed to create record".into()))
    }

    pub async fn find_record_by_field<T>(&self, table: &str, field: &str, value: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + Clone + Debug,
    {
        debug!("Finding record in table {} where {} = {}", table, field, value);
        
        let query = if field == "id" {
            format!("SELECT * FROM {} WHERE id = type::thing($value)", table)
        } else {
            format!("SELECT * FROM {} WHERE {} = $value", table, field)
        };

        debug!("执行查询: {}", query);
        debug!("查询参数: value = {}", value);
        
        let mut result = self.client
            .query(&query)
            .bind(("value", value.to_string()))
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {}", e)))?;
        
        debug!("原始查询结果: {:?}", result);
        
        let records: Vec<T> = result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse records: {}", e)))?;
            
        debug!("解析后的记录: {:?}", records);
        Ok(records.into_iter().next())
    }

    pub async fn update_record<T>(&self, table: &str, thing: &Thing, record: &T) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Debug + 'static,
    {
        debug!("Updating record in table {} with thing {:?}: {:?}", table, thing, record);
        
        let updated = self.client
            .update((thing.tb.clone(), thing.id.to_raw()))
            .content(record.clone())
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to update record: {}", e)))?;
            
        updated.ok_or_else(|| AuthError::DatabaseError("Record not found".into()))
    }

    pub async fn delete_record<T>(&self, table: &str, id: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + Clone + Debug,
    {
        debug!("Deleting record from table {} with id {}", table, id);
        
        let thing: Thing = format!("{}:{}", table, id).parse()
            .map_err(|_| AuthError::DatabaseError("Invalid record ID format".into()))?;
            
        let deleted = self.client
            .delete((thing.tb.clone(), thing.id.to_raw()))
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to delete record".into()))?;
            
        Ok(deleted)
    }

    pub async fn delete_session_by_token(&self, token: &str) -> Result<()> {
        let query = "DELETE session WHERE token = $token";
        self.client
            .query(query)
            .bind(("token", token.to_string()))
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
        let mut result = self.client
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
    pub fn query(&self, sql: &str) -> surrealdb::method::Query<'_, Client> {
        self.client.query(sql)
    }
}
