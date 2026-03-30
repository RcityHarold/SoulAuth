use std::{collections::HashMap, sync::Arc};

use serde::Serialize;
use tokio::sync::{broadcast, RwLock};

use crate::error::{AuthError, Result};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum SocialEvent {
    #[serde(rename = "friend_request_received")]
    FriendRequestReceived {
        request_id: String,
        requester_id: String,
        requester_username: String,
    },
    #[serde(rename = "friend_request_accepted")]
    FriendRequestAccepted {
        friend_user_id: String,
        friend_username: String,
    },
    #[serde(rename = "friend_request_rejected")]
    FriendRequestRejected {
        request_id: String,
        actor_user_id: String,
    },
    #[serde(rename = "direct_message_created")]
    DirectMessageCreated {
        conversation_id: String,
        message_id: String,
        sender_id: String,
    },
    #[serde(rename = "group_created")]
    GroupCreated {
        group_id: String,
    },
    #[serde(rename = "group_updated")]
    GroupUpdated {
        group_id: String,
    },
    #[serde(rename = "group_deleted")]
    GroupDeleted {
        group_id: String,
    },
    #[serde(rename = "group_thread_created")]
    GroupThreadCreated {
        group_id: String,
        thread_id: String,
        created_by: String,
    },
    #[serde(rename = "group_message_created")]
    GroupMessageCreated {
        group_id: String,
        thread_id: String,
        message_id: String,
        sender_id: String,
    },
    #[serde(rename = "group_collab_run_started")]
    GroupCollabRunStarted {
        group_id: String,
        thread_id: String,
        run_id: String,
        triggered_by: String,
    },
    #[serde(rename = "group_collab_run_completed")]
    GroupCollabRunCompleted {
        group_id: String,
        thread_id: String,
        run_id: String,
        status: String,
    },
}

#[derive(Clone, Default)]
pub struct SocialHub {
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<String>>>>,
}

impl SocialHub {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn subscribe(&self, user_id: &str) -> broadcast::Receiver<String> {
        let key = user_id.to_string();
        if let Some(sender) = self.channels.read().await.get(&key) {
            return sender.subscribe();
        }

        let mut channels = self.channels.write().await;
        let sender = channels.entry(key).or_insert_with(|| {
            let (sender, _) = broadcast::channel(256);
            sender
        });
        sender.subscribe()
    }

    pub async fn publish(&self, user_id: &str, event: &SocialEvent) -> Result<()> {
        let payload = serde_json::to_string(event)
            .map_err(|e| AuthError::ServerError(format!("Failed to serialize social event: {}", e)))?;
        let normalized = user_id.to_string();
        let sender = {
            let mut channels = self.channels.write().await;
            channels
                .entry(normalized)
                .or_insert_with(|| {
                    let (sender, _) = broadcast::channel(256);
                    sender
                })
                .clone()
        };

        let _ = sender.send(payload);
        Ok(())
    }
}
