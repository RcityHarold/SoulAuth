use crate::{
    config::Config,
    error::{AuthError, Result},
    models::direct_chat::{
        DirectConversation, DirectConversationView, DirectMessage, DirectMessageView,
        EnsureDirectConversationRequest, SendDirectMessageRequest,
    },
    models::friendship::{
        FriendRequest, FriendRequestActionResponse, FriendRequestStatus, FriendRequestView,
        FriendView, Friendship, RespondFriendRequestRequest, SendFriendRequestRequest,
    },
    models::group_chat::{
        CreateGroupThreadRequest, GroupThread, GroupThreadMessage, GroupThreadMessageView,
        GroupThreadView, SendGroupThreadMessageRequest,
    },
    models::group_collab::{
        CompleteGroupCollabRunRequest, CreateGroupCollabRunRequest, GroupCollabRun,
        GroupCollabRunView,
    },
    models::group::{
        AddGroupMembersRequest, CreateGroupRequest, GroupSettings, SocialGroup,
        TransferGroupOwnershipRequest, UpdateGroupAdminRequest, UpdateGroupAnnouncementRequest,
        UpdateGroupSettingsRequest,
    },
    models::group_member::SocialGroupMember,
    models::user::{CreateUserRequest, LoginRequest, AuthResponse, User, UserResponse, InitializePasswordRequest},
    models::password_reset::{RequestPasswordResetRequest, ResetPasswordRequest},
    models::session::{LogoutRequest, SessionInfo},
    services::auth::AuthService,
    services::social_hub::{SocialEvent, SocialHub},
    utils::record_id::record_id_key_to_string,
    utils::jwt::{decode_token_claims, Claims},
};
use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, ConnectInfo, Path, Query, State, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    routing::{get, post},
    Json, Router,
    Extension,
    response::IntoResponse,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use std::{sync::Arc, net::SocketAddr, future::Future};
use crate::{services::database::Database, utils::rate_limit_middleware::check_rate_limit_for_request, AppState};
use tracing::{error, info};
use serde_json::json;
use surrealdb::types::RecordId as Thing;
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    code: String,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SearchUserQuery {
    username: String,
}

#[derive(Debug, Deserialize)]
pub struct SocialWsQuery {
    token: String,
}

/// 获取客户端IP地址的辅助函数
fn get_client_ip(addr: &SocketAddr, headers: &HeaderMap) -> String {
    // 尝试从头部获取真实IP
    if let Some(forwarded_for) = headers.get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            if let Some(ip) = forwarded_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    if let Some(real_ip) = headers.get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }

    // 回退到连接地址
    addr.ip().to_string()
}

fn lockout_check_unavailable(scope: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": "Authentication service unavailable",
            "message": format!("{} lockout check unavailable", scope),
        })),
    )
}

async fn run_lockout_check_with_reauth<T, C, CFut, R, RFut>(
    scope: &str,
    check: C,
    reauth: R,
) -> std::result::Result<T, (StatusCode, Json<serde_json::Value>)>
where
    C: Fn() -> CFut,
    CFut: Future<Output = Result<T>>,
    R: Fn() -> RFut,
    RFut: Future<Output = Result<()>>,
{
    match check().await {
        Ok(result) => Ok(result),
        Err(e) => {
            error!("Failed to check {} lockout: {:?}", scope, e);
            match reauth().await {
                Ok(_) => match check().await {
                    Ok(result) => Ok(result),
                    Err(retry_err) => {
                        error!("{} lockout check still failed after reauth: {:?}", scope, retry_err);
                        Err(lockout_check_unavailable(scope))
                    }
                },
                Err(reauth_err) => {
                    error!("{} lockout check failed while reauthing: {:?}", scope, reauth_err);
                    Err(lockout_check_unavailable(scope))
                }
            }
        }
    }
}

pub fn router(db: Arc<Database>) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/verify-email/:token", get(verify_email))
        .route("/me", get(get_current_user))
        .route("/search-user", get(search_user_by_username))
        .route("/ws", get(social_ws))
        .route("/friend-requests", post(send_friend_request))
        .route("/friend-requests/incoming", get(list_incoming_friend_requests))
        .route("/friend-requests/outgoing", get(list_outgoing_friend_requests))
        .route("/friend-requests/:request_id/respond", post(respond_friend_request))
        .route("/friends", get(list_friends))
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/:group_id", post(update_group_settings).delete(dissolve_group))
        .route("/groups/:group_id/members", post(add_group_members))
        .route("/groups/:group_id/members/:member_id/remove", post(remove_group_member))
        .route("/groups/:group_id/leave", post(leave_group))
        .route("/groups/:group_id/admins", post(update_group_admin))
        .route("/groups/:group_id/owner", post(transfer_group_ownership))
        .route("/groups/:group_id/announcement", post(update_group_announcement))
        .route("/groups/:group_id/threads", get(list_group_threads).post(create_group_thread))
        .route(
            "/groups/:group_id/threads/:thread_id/messages",
            get(list_group_thread_messages).post(send_group_thread_message),
        )
        .route(
            "/groups/:group_id/threads/:thread_id/collab-runs",
            get(list_group_collab_runs).post(create_group_collab_run),
        )
        .route(
            "/groups/:group_id/threads/:thread_id/collab-runs/:run_id/complete",
            post(complete_group_collab_run),
        )
        .route("/direct-conversations", get(list_direct_conversations))
        .route("/direct-conversations/ensure", post(ensure_direct_conversation_route))
        .route("/direct-conversations/:conversation_id/messages", get(list_direct_messages))
        .route("/direct-messages", post(send_direct_message))
        .route("/initialize-password", post(initialize_password))
        .route("/request-password-reset", post(request_password_reset))
        .route("/reset-password", post(reset_password))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/sessions", get(get_sessions))
        // OAuth 路由
        .route("/login/google", get(google_login))
        .route("/callback/google", get(google_callback))
        .route("/login/github", get(github_login))
        .route("/callback/github", get(github_callback))
        .with_state(db)
}

// 注册处理函数
async fn register(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Extension(app_state): Extension<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> std::result::Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!("Starting user registration");
    
    // 获取客户端IP
    let client_ip = get_client_ip(&addr, &headers);
    
    // 检查速率限制
    check_rate_limit_for_request(&app_state.rate_limiter, &client_ip, "/api/auth/register").await?;
    
    let auth_service = AuthService::new(db, config).map_err(|e| {
        error!("Failed to create auth service: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Internal server error",
            "message": "Service unavailable"
        })))
    })?;
    
    let result = auth_service.register(req).await.map_err(|e| {
        error!("Registration failed: {:?}", e);
        let (status, message) = match e {
            AuthError::EmailExists => (StatusCode::CONFLICT, "Email already registered"),
            AuthError::UsernameExists => (StatusCode::CONFLICT, "Username already registered"),
            AuthError::ValidationError(_) => (StatusCode::BAD_REQUEST, "Invalid registration data"),
            AuthError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database error"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Registration failed"),
        };
        
        (status, Json(json!({
            "error": "Registration failed",
            "message": message
        })))
    })?;
    
    Ok(Json(result))
}

// 登录处理函数
async fn login(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Extension(app_state): Extension<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> std::result::Result<Json<AuthResponse>, (StatusCode, Json<serde_json::Value>)> {
    // 获取客户端IP
    let client_ip = get_client_ip(&addr, &headers);
    
    // 检查速率限制
    check_rate_limit_for_request(&app_state.rate_limiter, &client_ip, "/api/auth/login").await?;
    
    // 检查IP地址锁定
    let ip_lockout_result = run_lockout_check_with_reauth(
        "ip lockout",
        || app_state.lockout_service.check_ip_lockout(&client_ip),
        || async { app_state.db.reauth().await },
    )
    .await?;
    
    if ip_lockout_result.is_locked {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(json!({
            "error": "Account locked",
            "message": ip_lockout_result.message,
            "locked_until_seconds": ip_lockout_result.remaining_lockout_seconds
        }))));
    }
    
    // 检查用户账户锁定（如果我们能找到用户）
    // 注意：为了防止用户枚举攻击，我们需要小心处理这个检查
    let user_lockout_result = run_lockout_check_with_reauth(
        "user lockout",
        || app_state.lockout_service.check_user_lockout(&req.email),
        || async { app_state.db.reauth().await },
    )
    .await?;
    
    if user_lockout_result.is_locked {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(json!({
            "error": "Account locked",
            "message": user_lockout_result.message,
            "locked_until_seconds": user_lockout_result.remaining_lockout_seconds
        }))));
    }
    
    // 执行登录逻辑
    let auth_service = AuthService::new(db, config).map_err(|e| {
        error!("Failed to create auth service: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Internal server error",
            "message": "Service unavailable"
        })))
    })?;
    
    let response = auth_service.login(req.email.clone(), req.password).await.map_err(|e| {
        error!("Login failed: {:?}", e);
        
        // 在认证失败时记录锁定尝试
        let should_record_failure = matches!(e, 
            AuthError::InvalidCredentials | 
            AuthError::UserNotFound
        );
        
        if should_record_failure {
            // 异步记录失败尝试，不等待结果以避免阻塞响应
            let lockout_service = app_state.lockout_service.clone();
            let email = req.email.clone();
            let ip = client_ip.clone();
            
            tokio::spawn(async move {
                if let Err(e) = lockout_service.record_failed_user_attempt(&email).await {
                    error!("Failed to record user lockout attempt: {:?}", e);
                }
                if let Err(e) = lockout_service.record_failed_ip_attempt(&ip).await {
                    error!("Failed to record IP lockout attempt: {:?}", e);
                }
            });
        }
        
        let (status, message) = match e {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid email or password"),
            AuthError::EmailNotVerified => (StatusCode::FORBIDDEN, "Email not verified"),
            AuthError::UserNotFound => (StatusCode::UNAUTHORIZED, "Invalid email or password"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Login failed"),
        };
        
        (status, Json(json!({
            "error": "Authentication failed",
            "message": message
        })))
    })?;
    
    // 登录成功，重置失败尝试计数
    let lockout_service = app_state.lockout_service.clone();
    let email = req.email.clone();
    let ip = client_ip.clone();
    
    tokio::spawn(async move {
        if let Err(e) = lockout_service.reset_user_attempts(&email).await {
            error!("Failed to reset user attempts: {:?}", e);
        }
        if let Err(e) = lockout_service.reset_ip_attempts(&ip).await {
            error!("Failed to reset IP attempts: {:?}", e);
        }
    });
    
    Ok(Json(response))
}

// 邮箱验证处理函数
async fn verify_email(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<Json<AuthResponse>> {
    tracing::info!("Starting email verification");
    let auth_service = AuthService::new(db, config)?;
    let result = auth_service.verify_email(token).await;
    match result {
        Ok(auth_response) => Ok(Json(auth_response)),
        Err(e) => {
            error!("Email verification failed: {:?}", e);
            Err(e)
        }
    }
}

// 获取当前用户信息
async fn get_current_user(
    claims: Claims,
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<Json<UserResponse>> {
    let auth_service = AuthService::new(db, config)?;
    let user = auth_service
        .get_user_by_id(&claims.sub)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    Ok(Json(UserResponse::from(user)))
}

async fn search_user_by_username(
    _claims: Claims,
    State(db): State<Arc<Database>>,
    Query(query): Query<SearchUserQuery>,
) -> Result<Json<UserResponse>> {
    let username = query.username.trim().to_ascii_lowercase();
    if username.is_empty() {
        return Err(AuthError::ValidationError("username is required".to_string()));
    }

    let matched = db
        .find_record_by_field::<User>("user", "username_normalized", &username)
        .await?
        .ok_or(AuthError::NotFound("User not found".to_string()))?;

    Ok(Json(UserResponse::from(matched)))
}

async fn social_ws(
    ws: WebSocketUpgrade,
    Query(query): Query<SocialWsQuery>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
) -> std::result::Result<impl IntoResponse, StatusCode> {
    let claims = decode_token_claims(&query.token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let user_id = normalize_user_id(&claims.sub);
    Ok(ws.on_upgrade(move |socket| social_ws_session(socket, social_hub, user_id)))
}

async fn social_ws_session(mut socket: WebSocket, social_hub: Arc<SocialHub>, user_id: String) {
    let mut rx = social_hub.subscribe(&user_id).await;

    loop {
        tokio::select! {
            outbound = rx.recv() => {
                match outbound {
                    Ok(payload) => {
                        if socket.send(Message::Text(payload)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
}

fn user_thing(user_id: &str) -> Thing {
    Thing::new("user", normalize_user_id(user_id))
}

fn request_thing(request_id: &str) -> Thing {
    Thing::new("friend_request", normalize_request_id(request_id))
}

fn direct_conversation_thing(conversation_id: &str) -> Thing {
    Thing::new(
        "direct_conversation",
        normalize_direct_conversation_id(conversation_id),
    )
}

fn direct_message_thing(message_id: &str) -> Thing {
    Thing::new("direct_message", message_id.trim().to_string())
}

fn thing_key_string(thing: &Thing) -> String {
    record_id_key_to_string(thing)
}

fn surreal_user_id_string(user_id: &str) -> String {
    format!("user:`{}`", normalize_user_id(user_id))
}

fn surreal_request_id_string(request_id: &str) -> String {
    format!("friend_request:`{}`", normalize_request_id(request_id))
}

fn surreal_direct_conversation_id_string(conversation_id: &str) -> String {
    format!(
        "direct_conversation:`{}`",
        normalize_direct_conversation_id(conversation_id)
    )
}

fn normalize_user_id(user_id: &str) -> String {
    let trimmed = user_id.trim().trim_matches('`').trim();
    let without_prefix = trimmed.strip_prefix("user:").unwrap_or(trimmed);
    without_prefix
        .trim()
        .trim_start_matches('⟨')
        .trim_end_matches('⟩')
        .trim_matches('`')
        .to_string()
}

fn normalize_request_id(request_id: &str) -> String {
    let trimmed = request_id.trim().trim_matches('`').trim();
    let without_prefix = trimmed
        .strip_prefix("friend_request:")
        .unwrap_or(trimmed);
    without_prefix
        .trim()
        .trim_start_matches('⟨')
        .trim_end_matches('⟩')
        .trim_matches('`')
        .to_string()
}

fn normalize_direct_conversation_id(conversation_id: &str) -> String {
    let trimmed = conversation_id.trim().trim_matches('`').trim();
    let without_prefix = trimmed
        .strip_prefix("direct_conversation:")
        .unwrap_or(trimmed);
    without_prefix
        .trim()
        .trim_start_matches('⟨')
        .trim_end_matches('⟩')
        .trim_matches('`')
        .to_string()
}

fn normalize_group_id(group_id: &str) -> String {
    let trimmed = group_id
        .trim()
        .trim_matches('\\')
        .trim_matches('`')
        .trim();
    let without_prefix = trimmed.strip_prefix("social_group:").unwrap_or(trimmed);
    without_prefix
        .trim()
        .trim_start_matches('⟨')
        .trim_end_matches('⟩')
        .trim_matches('\\')
        .trim_matches('`')
        .to_string()
}

async fn persist_social_group_members(
    db: &Database,
    group_id: &str,
    member_ids: &[String],
    human_member_ids: &[String],
    member_user_ids: &[String],
) -> Result<SocialGroup> {
    let mut result = db
        .query(
            "UPDATE type::record('social_group', $group_id) SET member_ids = $member_ids, human_member_ids = $human_member_ids, member_user_ids = $member_user_ids RETURN AFTER"
        )
        .bind(("group_id", group_id.to_string()))
        .bind(("member_ids", member_ids.to_vec()))
        .bind(("human_member_ids", human_member_ids.to_vec()))
        .bind(("member_user_ids", member_user_ids.to_vec()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to persist social_group members: {}", e)))?;

    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse updated social_group: {}", e)))?;

    groups
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::DatabaseError("Updated social_group not found".to_string()))
}

async fn create_social_group_members(
    db: &Database,
    group_id: &str,
    human_member_ids: &[String],
    ai_member_ids: &[String],
    created_at: &str,
) -> Result<()> {
    for member_id in human_member_ids {
        let membership_id = Uuid::new_v4().to_string();
        db.query(
            "CREATE type::record('social_group_member', $membership_id) SET
                group_id = $group_id,
                member_id = $member_id,
                member_kind = 'human',
                created_at = $created_at"
        )
        .bind(("membership_id", membership_id))
        .bind(("group_id", group_id.to_string()))
        .bind(("member_id", member_id.clone()))
        .bind(("created_at", created_at.to_string()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to create human social_group_member: {}", e)))?;
    }

    for member_id in ai_member_ids {
        let membership_id = Uuid::new_v4().to_string();
        db.query(
            "CREATE type::record('social_group_member', $membership_id) SET
                group_id = $group_id,
                member_id = $member_id,
                member_kind = 'ai',
                created_at = $created_at"
        )
        .bind(("membership_id", membership_id))
        .bind(("group_id", group_id.to_string()))
        .bind(("member_id", member_id.clone()))
        .bind(("created_at", created_at.to_string()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to create ai social_group_member: {}", e)))?;
    }

    Ok(())
}

async fn load_social_group_members(
    db: &Database,
    group_id: &str,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut result = db
        .query("SELECT * FROM social_group_member WHERE group_id = $group_id")
        .bind(("group_id", group_id.to_string()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query social_group_member: {}", e)))?;

    let members: Vec<SocialGroupMember> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse social_group_member: {}", e)))?;

    let mut human_member_ids = Vec::new();
    let mut ai_member_ids = Vec::new();

    for member in members {
        match member.member_kind.as_str() {
            "ai" => {
                if !ai_member_ids.contains(&member.member_id) {
                    ai_member_ids.push(member.member_id);
                }
            }
            _ => {
                if !human_member_ids.contains(&member.member_id) {
                    human_member_ids.push(member.member_id);
                }
            }
        }
    }

    Ok((human_member_ids, ai_member_ids))
}

async fn hydrate_social_group(db: &Database, mut group: SocialGroup) -> Result<SocialGroup> {
    let group_id = group
        .id
        .as_ref()
        .map(|thing| normalize_group_id(&thing_key_string(thing)))
        .ok_or_else(|| AuthError::DatabaseError("social_group missing id".to_string()))?;

    let (human_member_ids, ai_member_ids) = load_social_group_members(db, &group_id).await?;
    group.member_user_ids = human_member_ids.clone();
    group.human_member_ids = human_member_ids.clone();
    group.member_ids = if group.group_type == 2 {
        human_member_ids
    } else {
        Vec::new()
    };
    group.ai_member_ids = ai_member_ids;
    Ok(group)
}

fn map_group_thread_view(thread: GroupThread) -> GroupThreadView {
    GroupThreadView {
        id: thread
            .id
            .as_ref()
            .map(thing_key_string)
            .unwrap_or_default(),
        group_id: thread.group_id,
        thread_type: thread.thread_type,
        title: thread.title,
        created_by: thread.created_by,
        status: thread.status,
        created_at: thread.created_at,
        updated_at: thread.updated_at,
    }
}

fn map_group_thread_message_view(message: GroupThreadMessage) -> GroupThreadMessageView {
    GroupThreadMessageView {
        id: message
            .id
            .as_ref()
            .map(thing_key_string)
            .unwrap_or_default(),
        group_id: message.group_id,
        thread_id: message.thread_id,
        sender_id: message.sender_id,
        sender_kind: message.sender_kind,
        message_type: message.message_type,
        content: message.content,
        reply_to: message.reply_to,
        created_at: message.created_at,
    }
}

fn map_group_collab_run_view(run: GroupCollabRun) -> GroupCollabRunView {
    GroupCollabRunView {
        id: run
            .id
            .as_ref()
            .map(thing_key_string)
            .unwrap_or_default(),
        group_id: run.group_id,
        thread_id: run.thread_id,
        scenario_type: run.scenario_type,
        triggered_by: run.triggered_by,
        strategy_type: run.strategy_type,
        status: run.status,
        prompt: run.prompt,
        participant_ids: run.participant_ids,
        metadata: run.metadata,
        result_summary: run.result_summary,
        result_payload: run.result_payload,
        created_at: run.created_at,
        updated_at: run.updated_at,
        completed_at: run.completed_at,
    }
}

fn group_supports_threads(group_type: u8) -> bool {
    matches!(group_type, 2 | 6 | 7 | 9)
}

fn group_supports_ai_collab(group_type: u8) -> bool {
    matches!(group_type, 6 | 7 | 9)
}

fn group_human_can_post(group_type: u8) -> bool {
    matches!(group_type, 2 | 6 | 9)
}

async fn ensure_group_thread_access(
    db: &Database,
    current_user_id: &str,
    group_id: &str,
    thread_id: &str,
) -> Result<SocialGroup> {
    let group = ensure_group_access(db, current_user_id, group_id).await?;
    if !group_supports_threads(group.group_type) {
        return Err(AuthError::BadRequest("This group type does not support threads".to_string()));
    }

    let mut result = db
        .query("SELECT * FROM group_thread WHERE id = type::record('group_thread', $thread_id) AND group_id = $group_id LIMIT 1")
        .bind(("thread_id", thread_id.to_string()))
        .bind(("group_id", group_id.to_string()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query group_thread: {}", e)))?;
    let threads: Vec<GroupThread> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse group_thread: {}", e)))?;
    if threads.is_empty() {
        return Err(AuthError::NotFound("Thread not found".to_string()));
    }

    Ok(group)
}

async fn create_default_group_thread(db: &Database, group_id: &str, created_by: &str) -> Result<GroupThread> {
    let now = chrono::Utc::now().to_rfc3339();
    let thread_id = Uuid::new_v4().to_string();
    let mut result = db
        .query(
            "CREATE type::record('group_thread', $thread_id) SET
                group_id = $group_id,
                thread_type = $thread_type,
                title = $title,
                created_by = $created_by,
                status = $status,
                created_at = $created_at,
                updated_at = $updated_at
             RETURN AFTER",
        )
        .bind(("thread_id", thread_id))
        .bind(("group_id", group_id.to_string()))
        .bind(("thread_type", "chat".to_string()))
        .bind(("title", "主会话".to_string()))
        .bind(("created_by", created_by.to_string()))
        .bind(("status", "active".to_string()))
        .bind(("created_at", now.clone()))
        .bind(("updated_at", now))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to create default group_thread: {}", e)))?;

    let threads: Vec<GroupThread> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse created default group_thread: {}", e)))?;

    threads
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::DatabaseError("Created default group_thread not found".to_string()))
}

async fn ensure_group_access(
    db: &Database,
    current_user_id: &str,
    group_id: &str,
) -> Result<SocialGroup> {
    let mut result = db
        .query("SELECT * FROM social_group WHERE id = type::record('social_group', $group_id) LIMIT 1")
        .bind(("group_id", group_id.to_string()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query social_group: {}", e)))?;
    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse social_group: {}", e)))?;
    let group = groups
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::NotFound("Group not found".to_string()))?;
    let group = hydrate_social_group(db, group).await?;
    let is_member = group.owner_id == current_user_id || group.member_user_ids.contains(&current_user_id.to_string());
    if !is_member {
        return Err(AuthError::Forbidden("You are not a member of this group".to_string()));
    }
    Ok(group)
}

async fn ensure_group_admin_access(
    db: &Database,
    current_user_id: &str,
    group_id: &str,
) -> Result<SocialGroup> {
    let group = ensure_group_access(db, current_user_id, group_id).await?;
    if group.group_type != 2 {
        return Err(AuthError::BadRequest("This management action is currently only enabled for scenario 2".to_string()));
    }
    if group.owner_id != current_user_id && !group.admin_ids.contains(&current_user_id.to_string()) {
        return Err(AuthError::Forbidden("You do not have permission to manage this group".to_string()));
    }
    Ok(group)
}

async fn load_group_by_id(db: &Database, group_id: &str) -> Result<SocialGroup> {
    let mut result = db
        .query("SELECT * FROM social_group WHERE id = type::record('social_group', $group_id) LIMIT 1")
        .bind(("group_id", group_id.to_string()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query social_group: {}", e)))?;
    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse social_group: {}", e)))?;
    let group = groups
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::NotFound("Group not found".to_string()))?;
    hydrate_social_group(db, group).await
}

async fn remove_social_group_member(db: &Database, group_id: &str, member_id: &str) -> Result<()> {
    db.query("DELETE social_group_member WHERE group_id = $group_id AND member_id = $member_id")
        .bind(("group_id", group_id.to_string()))
        .bind(("member_id", member_id.to_string()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to delete social_group_member: {}", e)))?;
    Ok(())
}

async fn publish_group_updated(
    social_hub: &SocialHub,
    group_id: &str,
    member_ids: &[String],
) {
    for member_id in member_ids {
        let _ = social_hub
            .publish(
                member_id,
                &SocialEvent::GroupUpdated {
                    group_id: group_id.to_string(),
                },
            )
            .await;
    }
}

async fn create_social_group_record(db: &Database, group: &SocialGroup) -> Result<SocialGroup> {
    let group_id = group
        .id
        .as_ref()
        .map(thing_key_string)
        .ok_or_else(|| AuthError::DatabaseError("social_group missing id".to_string()))?;

    let mut result = db
        .query(
            "CREATE type::record('social_group', $group_id) SET
                name = $name,
                avatar = $avatar,
                type = $group_type,
                level = $level,
                ownerId = $owner_id,
                created_at = $created_at,
                admin_ids = $admin_ids,
                member_ids = $member_ids,
                announcement = $announcement,
                settings = $settings,
                code = $code,
                human_member_ids = $human_member_ids,
                ai_member_ids = $ai_member_ids,
                description = $description,
                max_humans = $max_humans,
                max_ais = $max_ais,
                member_user_ids = $member_user_ids
             RETURN AFTER"
        )
        .bind(("group_id", group_id))
        .bind(("name", group.name.clone()))
        .bind(("avatar", group.avatar.clone()))
        .bind(("group_type", group.group_type))
        .bind(("level", group.level.clone()))
        .bind(("owner_id", group.owner_id.clone()))
        .bind(("created_at", group.created_at.clone()))
        .bind(("admin_ids", group.admin_ids.clone()))
        .bind(("member_ids", group.member_ids.clone()))
        .bind(("announcement", group.announcement.clone()))
        .bind(("settings", group.settings.clone()))
        .bind(("code", group.code.clone()))
        .bind(("human_member_ids", group.human_member_ids.clone()))
        .bind(("ai_member_ids", group.ai_member_ids.clone()))
        .bind(("description", group.description.clone()))
        .bind(("max_humans", group.max_humans))
        .bind(("max_ais", group.max_ais))
        .bind(("member_user_ids", group.member_user_ids.clone()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to create social_group: {}", e)))?;

    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse created social_group: {}", e)))?;

    groups
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::DatabaseError("Created social_group not found".to_string()))
}

async fn list_group_threads(
    claims: Claims,
    Path(group_id): Path<String>,
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<GroupThreadView>>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_access(&db, &current_user_id, &group_id).await?;
    if !group_supports_threads(group.group_type) {
        return Err(AuthError::BadRequest("This group type does not support threads".to_string()));
    }

    let mut result = db
        .query("SELECT * FROM group_thread WHERE group_id = $group_id ORDER BY updated_at DESC")
        .bind(("group_id", group_id.clone()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query group_thread: {}", e)))?;
    let threads: Vec<GroupThread> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse group_thread: {}", e)))?;

    Ok(Json(threads.into_iter().map(map_group_thread_view).collect()))
}

async fn create_group_thread(
    claims: Claims,
    Path(group_id): Path<String>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<CreateGroupThreadRequest>,
) -> Result<Json<GroupThreadView>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_access(&db, &current_user_id, &group_id).await?;
    if !group_supports_threads(group.group_type) {
        return Err(AuthError::BadRequest("This group type does not support threads".to_string()));
    }

    let title = req.title.trim();
    if title.is_empty() {
        return Err(AuthError::ValidationError("Thread title is required".to_string()));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let thread_id = Uuid::new_v4().to_string();
    let mut result = db
        .query(
            "CREATE type::record('group_thread', $thread_id) SET
                group_id = $group_id,
                thread_type = $thread_type,
                title = $title,
                created_by = $created_by,
                status = $status,
                created_at = $created_at,
                updated_at = $updated_at
             RETURN AFTER",
        )
        .bind(("thread_id", thread_id))
        .bind(("group_id", group_id.clone()))
        .bind(("thread_type", "chat".to_string()))
        .bind(("title", title.to_string()))
        .bind(("created_by", current_user_id.clone()))
        .bind(("status", "active".to_string()))
        .bind(("created_at", now.clone()))
        .bind(("updated_at", now))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to create group_thread: {}", e)))?;
    let threads: Vec<GroupThread> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse created group_thread: {}", e)))?;
    let created = threads
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::DatabaseError("Created group_thread not found".to_string()))?;
    let view = map_group_thread_view(created);

    for member_id in group.member_user_ids.iter() {
        let _ = social_hub
            .publish(
                member_id,
                &SocialEvent::GroupThreadCreated {
                    group_id: group_id.clone(),
                    thread_id: view.id.clone(),
                    created_by: current_user_id.clone(),
                },
            )
            .await;
    }

    Ok(Json(view))
}

async fn list_group_thread_messages(
    claims: Claims,
    Path((group_id, thread_id)): Path<(String, String)>,
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<GroupThreadMessageView>>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let _group = ensure_group_thread_access(&db, &current_user_id, &group_id, &thread_id).await?;

    let mut result = db
        .query("SELECT * FROM group_thread_message WHERE group_id = $group_id AND thread_id = $thread_id ORDER BY created_at ASC")
        .bind(("group_id", group_id))
        .bind(("thread_id", thread_id))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query group_thread_message: {}", e)))?;
    let messages: Vec<GroupThreadMessage> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse group_thread_message: {}", e)))?;

    Ok(Json(messages.into_iter().map(map_group_thread_message_view).collect()))
}

async fn send_group_thread_message(
    claims: Claims,
    Path((group_id, thread_id)): Path<(String, String)>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<SendGroupThreadMessageRequest>,
) -> Result<Json<GroupThreadMessageView>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_thread_access(&db, &current_user_id, &group_id, &thread_id).await?;
    if !group_human_can_post(group.group_type) {
        return Err(AuthError::Forbidden("Human members cannot post directly in this group".to_string()));
    }

    let content = req.content.trim();
    if content.is_empty() {
        return Err(AuthError::ValidationError("Message content is required".to_string()));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let message_id = Uuid::new_v4().to_string();
    let reply_to = req.reply_to;
    let mut result = db
        .query(
            "CREATE type::record('group_thread_message', $message_id) SET
                group_id = $group_id,
                thread_id = $thread_id,
                sender_id = $sender_id,
                sender_kind = $sender_kind,
                message_type = $message_type,
                content = $content,
                reply_to = $reply_to,
                created_at = $created_at
             RETURN AFTER",
        )
        .bind(("message_id", message_id))
        .bind(("group_id", group_id.clone()))
        .bind(("thread_id", thread_id.clone()))
        .bind(("sender_id", current_user_id.clone()))
        .bind(("sender_kind", "human".to_string()))
        .bind(("message_type", "text".to_string()))
        .bind(("content", content.to_string()))
        .bind(("reply_to", reply_to))
        .bind(("created_at", now.clone()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to create group_thread_message: {}", e)))?;
    let messages: Vec<GroupThreadMessage> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse created group_thread_message: {}", e)))?;
    let created = messages
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::DatabaseError("Created group_thread_message not found".to_string()))?;

    let _ = db
        .query("UPDATE group_thread SET updated_at = $updated_at WHERE id = type::record('group_thread', $thread_id)")
        .bind(("updated_at", now))
        .bind(("thread_id", thread_id.clone()))
        .await;

    let view = map_group_thread_message_view(created);

    for member_id in group.member_user_ids.iter() {
        let _ = social_hub
            .publish(
                member_id,
                &SocialEvent::GroupMessageCreated {
                    group_id: group_id.clone(),
                    thread_id: thread_id.clone(),
                    message_id: view.id.clone(),
                    sender_id: current_user_id.clone(),
                },
            )
            .await;
    }

    Ok(Json(view))
}

async fn list_group_collab_runs(
    claims: Claims,
    Path((group_id, thread_id)): Path<(String, String)>,
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<GroupCollabRunView>>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_thread_access(&db, &current_user_id, &group_id, &thread_id).await?;
    if !group_supports_ai_collab(group.group_type) {
        return Err(AuthError::BadRequest("This group type does not support collaboration runs".to_string()));
    }

    let mut result = db
        .query("SELECT * FROM group_collab_run WHERE group_id = $group_id AND thread_id = $thread_id ORDER BY created_at DESC")
        .bind(("group_id", group_id))
        .bind(("thread_id", thread_id))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query group_collab_run: {}", e)))?;
    let runs: Vec<GroupCollabRun> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse group_collab_run: {}", e)))?;

    Ok(Json(runs.into_iter().map(map_group_collab_run_view).collect()))
}

async fn create_group_collab_run(
    claims: Claims,
    Path((group_id, thread_id)): Path<(String, String)>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<CreateGroupCollabRunRequest>,
) -> Result<Json<GroupCollabRunView>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_thread_access(&db, &current_user_id, &group_id, &thread_id).await?;
    if !group_supports_ai_collab(group.group_type) {
        return Err(AuthError::BadRequest("This group type does not support collaboration runs".to_string()));
    }

    let prompt = req.prompt.trim();
    let strategy_type = req.strategy_type.trim();
    if prompt.is_empty() {
        return Err(AuthError::ValidationError("Collaboration prompt is required".to_string()));
    }
    if strategy_type.is_empty() {
        return Err(AuthError::ValidationError("Strategy type is required".to_string()));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let participant_ids = normalize_unique_ids(req.participant_ids);
    let run = GroupCollabRun {
        id: Some(Thing::new("group_collab_run", Uuid::new_v4().to_string())),
        group_id: group_id.clone(),
        thread_id: thread_id.clone(),
        scenario_type: group.group_type,
        triggered_by: current_user_id.clone(),
        strategy_type: strategy_type.to_string(),
        status: "requested".to_string(),
        prompt: prompt.to_string(),
        participant_ids,
        metadata: req.metadata,
        result_summary: None,
        result_payload: None,
        created_at: now.clone(),
        updated_at: now,
        completed_at: None,
    };
    let created: GroupCollabRun = db.create_record("group_collab_run", &run).await?;
    let view = map_group_collab_run_view(created);

    for member_id in group.member_user_ids.iter() {
        let _ = social_hub
            .publish(
                member_id,
                &SocialEvent::GroupCollabRunStarted {
                    group_id: group_id.clone(),
                    thread_id: thread_id.clone(),
                    run_id: view.id.clone(),
                    triggered_by: current_user_id.clone(),
                },
            )
            .await;
    }

    Ok(Json(view))
}

async fn complete_group_collab_run(
    claims: Claims,
    Path((group_id, thread_id, run_id)): Path<(String, String, String)>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<CompleteGroupCollabRunRequest>,
) -> Result<Json<GroupCollabRunView>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_thread_access(&db, &current_user_id, &group_id, &thread_id).await?;
    if !group_supports_ai_collab(group.group_type) {
        return Err(AuthError::BadRequest("This group type does not support collaboration runs".to_string()));
    }

    let status = req.status.trim();
    if status.is_empty() {
        return Err(AuthError::ValidationError("Status is required".to_string()));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let mut result = db
        .query("UPDATE type::record('group_collab_run', $run_id) SET status = $status, result_summary = $result_summary, result_payload = $result_payload, updated_at = $updated_at, completed_at = $completed_at RETURN AFTER")
        .bind(("run_id", run_id.clone()))
        .bind(("status", status.to_string()))
        .bind(("result_summary", req.result_summary.clone()))
        .bind(("result_payload", req.result_payload.clone()))
        .bind(("updated_at", now.clone()))
        .bind(("completed_at", Some(now)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to update group_collab_run: {}", e)))?;
    let runs: Vec<GroupCollabRun> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse updated group_collab_run: {}", e)))?;
    let updated = runs
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::NotFound("Collaboration run not found".to_string()))?;
    if updated.group_id != group_id || updated.thread_id != thread_id {
        return Err(AuthError::Forbidden("Collaboration run does not belong to this thread".to_string()));
    }

    let view = map_group_collab_run_view(updated);
    for member_id in group.member_user_ids.iter() {
        let _ = social_hub
            .publish(
                member_id,
                &SocialEvent::GroupCollabRunCompleted {
                    group_id: group_id.clone(),
                    thread_id: thread_id.clone(),
                    run_id: view.id.clone(),
                    status: view.status.clone(),
                },
            )
            .await;
    }

    Ok(Json(view))
}

fn ts_to_rfc3339(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339())
}

fn generate_group_code() -> String {
    Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(8)
        .collect::<String>()
        .to_uppercase()
}

fn default_group_avatar(group_type: u8) -> &'static str {
    match group_type {
        2 => "/groups/default.png",
        6 => "/groups/brain-trust.png",
        9 => "/groups/mixed.png",
        _ => "/groups/default.png",
    }
}

fn normalize_unique_ids(ids: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for id in ids {
        let normalized = normalize_user_id(&id);
        if !normalized.is_empty() && seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn canonical_friend_pair(left: &str, right: &str) -> (String, String) {
    let left = normalize_user_id(left);
    let right = normalize_user_id(right);
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

async fn ensure_user_exists(db: &Arc<Database>, user_id: &str) -> Result<User> {
    let normalized = normalize_user_id(user_id);
    let mut result = db
        .query("SELECT * FROM user WHERE <string>id = $user_id LIMIT 1")
        .bind(("user_id", surreal_user_id_string(&normalized)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query user: {}", e)))?;
    let users: Vec<User> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse user: {}", e)))?;
    users.into_iter().next().ok_or_else(|| {
        error!("User not found while resolving friend flow: {}", normalized);
        AuthError::UserNotFound
    })
}

async fn find_friend_request_by_id(db: &Arc<Database>, request_id: &str) -> Result<FriendRequest> {
    let normalized = normalize_request_id(request_id);
    let mut result = db
        .query("SELECT * FROM friend_request WHERE <string>id = $request_id LIMIT 1")
        .bind(("request_id", surreal_request_id_string(&normalized)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query friend request: {}", e)))?;
    let requests: Vec<FriendRequest> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse friend request: {}", e)))?;
    requests
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::NotFound("Friend request not found".to_string()))
}

async fn friendship_exists(db: &Arc<Database>, left: &str, right: &str) -> Result<bool> {
    let (a, b) = canonical_friend_pair(left, right);
    let query = "SELECT * FROM friendship WHERE <string>user_a = $user_a AND <string>user_b = $user_b LIMIT 1";
    let mut result = db
        .query(query)
        .bind(("user_a", surreal_user_id_string(&a)))
        .bind(("user_b", surreal_user_id_string(&b)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query friendship: {}", e)))?;
    let items: Vec<Friendship> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse friendship: {}", e)))?;
    Ok(!items.is_empty())
}

async fn find_direct_conversation(
    db: &Arc<Database>,
    left: &str,
    right: &str,
) -> Result<Option<DirectConversation>> {
    let (a, b) = canonical_friend_pair(left, right);
    let query = "SELECT * FROM direct_conversation WHERE <string>user_a = $user_a AND <string>user_b = $user_b LIMIT 1";
    let mut result = db
        .query(query)
        .bind(("user_a", surreal_user_id_string(&a)))
        .bind(("user_b", surreal_user_id_string(&b)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query direct conversation: {}", e)))?;
    let items: Vec<DirectConversation> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse direct conversation: {}", e)))?;
    Ok(items.into_iter().next())
}

async fn ensure_direct_conversation(
    db: &Arc<Database>,
    requester_id: &str,
    target_user_id: &str,
) -> Result<DirectConversation> {
    if !friendship_exists(db, requester_id, target_user_id).await? {
        return Err(AuthError::Forbidden("Only friends can start private chats".to_string()));
    }

    if let Some(existing) = find_direct_conversation(db, requester_id, target_user_id).await? {
        return Ok(existing);
    }

    let (user_a, user_b) = canonical_friend_pair(requester_id, target_user_id);
    let now = chrono::Utc::now().timestamp();
    let conversation = DirectConversation {
        id: Some(Thing::new("direct_conversation", Uuid::new_v4().to_string())),
        user_a: user_thing(&user_a),
        user_b: user_thing(&user_b),
        created_at: now,
        updated_at: now,
    };
    db.create_record("direct_conversation", &conversation).await
}

async fn latest_direct_message_content(
    db: &Arc<Database>,
    conversation_id: &str,
) -> Result<Option<(String, String)>> {
    let query = r#"
        SELECT * FROM direct_message
        WHERE <string>conversation_id = $conversation_id
        ORDER BY created_at DESC
        LIMIT 1
    "#;
    let mut result = db
        .query(query)
        .bind(("conversation_id", surreal_direct_conversation_id_string(conversation_id)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query direct messages: {}", e)))?;
    let items: Vec<DirectMessage> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse direct messages: {}", e)))?;
    Ok(items
        .into_iter()
        .next()
        .map(|item| (item.content, ts_to_rfc3339(item.created_at))))
}

async fn direct_conversation_view_for(
    db: &Arc<Database>,
    viewer_id: &str,
    conversation: DirectConversation,
) -> Result<DirectConversationView> {
    let conversation_id = conversation
        .id
        .as_ref()
        .map(thing_key_string)
        .unwrap_or_default();
    let left_id = normalize_user_id(&thing_key_string(&conversation.user_a));
    let right_id = normalize_user_id(&thing_key_string(&conversation.user_b));
    let normalized_viewer = normalize_user_id(viewer_id);
    let peer_user_id = if left_id == normalized_viewer {
        right_id
    } else {
        left_id
    };
    let peer = ensure_user_exists(db, &peer_user_id).await?;
    let last_message = latest_direct_message_content(db, &conversation_id).await?;

    Ok(DirectConversationView {
        conversation_id,
        peer_user_id,
        peer_username: peer.username,
        last_message: last_message.as_ref().map(|value| value.0.clone()),
        last_message_at: last_message.as_ref().map(|value| value.1.clone()),
        created_at: ts_to_rfc3339(conversation.created_at),
    })
}

fn map_direct_message_view(message: DirectMessage) -> DirectMessageView {
    DirectMessageView {
        id: message
            .id
            .as_ref()
            .map(thing_key_string)
            .unwrap_or_default(),
        conversation_id: normalize_direct_conversation_id(&thing_key_string(&message.conversation_id)),
        sender_id: normalize_user_id(&thing_key_string(&message.sender_id)),
        recipient_id: normalize_user_id(&thing_key_string(&message.recipient_id)),
        content: message.content,
        created_at: ts_to_rfc3339(message.created_at),
    }
}

async fn pending_request_exists(db: &Arc<Database>, left: &str, right: &str) -> Result<bool> {
    let left = normalize_user_id(left);
    let right = normalize_user_id(right);
    let query = r#"
        SELECT * FROM friend_request
        WHERE status = 'Pending'
          AND (
            (<string>requester_id = $left_user AND <string>addressee_id = $right_user)
            OR
            (<string>requester_id = $right_user AND <string>addressee_id = $left_user)
          )
        LIMIT 1
    "#;
    let mut result = db
        .query(query)
        .bind(("left_user", surreal_user_id_string(&left)))
        .bind(("right_user", surreal_user_id_string(&right)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query friend requests: {}", e)))?;
    let items: Vec<FriendRequest> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse friend requests: {}", e)))?;
    Ok(!items.is_empty())
}

async fn map_request_view(db: &Arc<Database>, request: FriendRequest) -> Result<FriendRequestView> {
    let requester_id = normalize_user_id(&thing_key_string(&request.requester_id));
    let addressee_id = normalize_user_id(&thing_key_string(&request.addressee_id));
    let requester = ensure_user_exists(db, &requester_id).await?;
    let addressee = ensure_user_exists(db, &addressee_id).await?;

    Ok(FriendRequestView {
        request_id: request
            .id
            .as_ref()
            .map(thing_key_string)
            .unwrap_or_default(),
        requester_id,
        requester_username: requester.username,
        addressee_id,
        addressee_username: addressee.username,
        status: request.status,
        message: request.message,
        created_at: request.created_at,
        responded_at: request.responded_at,
    })
}

async fn send_friend_request(
    claims: Claims,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<SendFriendRequestRequest>,
) -> Result<Json<FriendRequestActionResponse>> {
    let requester_id = normalize_user_id(&claims.sub);
    let target_user_id = normalize_user_id(req.target_user_id.trim());

    if target_user_id.is_empty() {
        return Err(AuthError::ValidationError("Target user is required".to_string()));
    }
    if requester_id == target_user_id {
        return Err(AuthError::ValidationError("Cannot add yourself as a friend".to_string()));
    }

    let _ = ensure_user_exists(&db, &requester_id).await?;
    let _ = ensure_user_exists(&db, &target_user_id).await?;

    if friendship_exists(&db, &requester_id, &target_user_id).await? {
        return Err(AuthError::ValidationError("You are already friends".to_string()));
    }

    if pending_request_exists(&db, &requester_id, &target_user_id).await? {
        return Err(AuthError::ValidationError("A pending friend request already exists".to_string()));
    }

    let request_id = Uuid::new_v4().to_string();
    let request = FriendRequest {
        id: Some(Thing::new("friend_request", request_id.clone())),
        requester_id: user_thing(&requester_id),
        addressee_id: user_thing(&target_user_id),
        status: FriendRequestStatus::Pending.as_str().to_string(),
        message: req.message.filter(|value| !value.trim().is_empty()),
        created_at: chrono::Utc::now().timestamp(),
        responded_at: None,
    };

    let _created: FriendRequest = db.create_record("friend_request", &request).await?;
    let requester = ensure_user_exists(&db, &requester_id).await?;

    let _ = social_hub
        .publish(
            &target_user_id,
            &SocialEvent::FriendRequestReceived {
                request_id: request_id.clone(),
                requester_id: requester_id.clone(),
                requester_username: requester.username.clone(),
            },
        )
        .await;

    Ok(Json(FriendRequestActionResponse {
        request_id,
        status: FriendRequestStatus::Pending.as_str().to_string(),
        message: "Friend request sent. Waiting for approval.".to_string(),
    }))
}

async fn list_incoming_friend_requests(
    claims: Claims,
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<FriendRequestView>>> {
    let query = r#"
        SELECT * FROM friend_request
        WHERE <string>addressee_id = $user_id AND status = 'Pending'
        ORDER BY created_at DESC
    "#;
    let mut result = db
        .query(query)
        .bind(("user_id", surreal_user_id_string(&claims.sub)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query incoming requests: {}", e)))?;
    let requests: Vec<FriendRequest> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse incoming requests: {}", e)))?;

    let mut views = Vec::with_capacity(requests.len());
    for request in requests {
        views.push(map_request_view(&db, request).await?);
    }
    Ok(Json(views))
}

async fn list_outgoing_friend_requests(
    claims: Claims,
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<FriendRequestView>>> {
    let query = r#"
        SELECT * FROM friend_request
        WHERE <string>requester_id = $user_id AND status = 'Pending'
        ORDER BY created_at DESC
    "#;
    let mut result = db
        .query(query)
        .bind(("user_id", surreal_user_id_string(&claims.sub)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query outgoing requests: {}", e)))?;
    let requests: Vec<FriendRequest> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse outgoing requests: {}", e)))?;

    let mut views = Vec::with_capacity(requests.len());
    for request in requests {
        views.push(map_request_view(&db, request).await?);
    }
    Ok(Json(views))
}

async fn respond_friend_request(
    claims: Claims,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
    Json(req): Json<RespondFriendRequestRequest>,
) -> Result<Json<FriendRequestActionResponse>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let request = find_friend_request_by_id(&db, &request_id).await?;

    if normalize_user_id(&thing_key_string(&request.addressee_id)) != current_user_id {
        return Err(AuthError::Forbidden("You can only respond to your own incoming requests".to_string()));
    }
    if request.status != FriendRequestStatus::Pending.as_str() {
        return Err(AuthError::ValidationError("This friend request has already been processed".to_string()));
    }

    let new_status = if req.accept {
        FriendRequestStatus::Accepted.as_str().to_string()
    } else {
        FriendRequestStatus::Rejected.as_str().to_string()
    };
    let responded_at = chrono::Utc::now().timestamp();

    let query = "UPDATE $request_id SET status = $status, responded_at = $responded_at";
    let mut result = db
        .query(query)
        .bind(("request_id", request_thing(&request_id)))
        .bind(("status", new_status.clone()))
        .bind(("responded_at", responded_at))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to update friend request: {}", e)))?;
    let _updated: Vec<FriendRequest> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse updated friend request: {}", e)))?;

    if req.accept {
        let requester_id = normalize_user_id(&thing_key_string(&request.requester_id));
        let addressee_id = normalize_user_id(&thing_key_string(&request.addressee_id));
        if !friendship_exists(&db, &requester_id, &addressee_id).await? {
            let (a, b) = canonical_friend_pair(&requester_id, &addressee_id);
            let friendship = Friendship {
                id: Some(Thing::new("friendship", Uuid::new_v4().to_string())),
                user_a: user_thing(&a),
                user_b: user_thing(&b),
                created_at: responded_at,
                created_from_request_id: Some(request_thing(&request_id)),
            };
            let _created: Friendship = db.create_record("friendship", &friendship).await?;
        }
        let requester = ensure_user_exists(&db, &requester_id).await?;
        let addressee = ensure_user_exists(&db, &addressee_id).await?;
        let _ = social_hub
            .publish(
                &requester_id,
                &SocialEvent::FriendRequestAccepted {
                    friend_user_id: addressee_id.clone(),
                    friend_username: addressee.username.clone(),
                },
            )
            .await;
        let _ = social_hub
            .publish(
                &addressee_id,
                &SocialEvent::FriendRequestAccepted {
                    friend_user_id: requester_id.clone(),
                    friend_username: requester.username.clone(),
                },
            )
            .await;
    } else {
        let requester_id = normalize_user_id(&thing_key_string(&request.requester_id));
        let addressee_id = normalize_user_id(&thing_key_string(&request.addressee_id));
        let _ = social_hub
            .publish(
                &requester_id,
                &SocialEvent::FriendRequestRejected {
                    request_id: request_id.clone(),
                    actor_user_id: addressee_id,
                },
            )
            .await;
    }

    Ok(Json(FriendRequestActionResponse {
        request_id,
        status: new_status.clone(),
        message: if req.accept {
            "Friend request accepted.".to_string()
        } else {
            "Friend request rejected.".to_string()
        },
    }))
}

async fn list_friends(
    claims: Claims,
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<FriendView>>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let query = r#"
        SELECT * FROM friendship
        WHERE <string>user_a = $user_id OR <string>user_b = $user_id
        ORDER BY created_at DESC
    "#;
    let mut result = db
        .query(query)
        .bind(("user_id", surreal_user_id_string(&current_user_id)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query friends: {}", e)))?;
    let friendships: Vec<Friendship> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse friendships: {}", e)))?;

    let mut friends = Vec::with_capacity(friendships.len());
    for friendship in friendships {
        let left_id = normalize_user_id(&thing_key_string(&friendship.user_a));
        let right_id = normalize_user_id(&thing_key_string(&friendship.user_b));
        let friend_id = if left_id == current_user_id { right_id } else { left_id };
        let user = ensure_user_exists(&db, &friend_id).await?;
        friends.push(FriendView {
            user_id: friend_id,
            username: user.username,
            created_at: friendship.created_at,
        });
    }

    Ok(Json(friends))
}

async fn list_groups(
    claims: Claims,
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<SocialGroup>>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let mut membership_result = db
        .query("SELECT * FROM social_group_member WHERE member_id = $member_id AND member_kind = 'human'")
        .bind(("member_id", current_user_id.clone()))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query social_group_member: {}", e)))?;
    let memberships: Vec<SocialGroupMember> = membership_result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse social_group_member: {}", e)))?;

    let mut group_ids = Vec::new();
    for membership in memberships {
        if !group_ids.contains(&membership.group_id) {
            group_ids.push(membership.group_id);
        }
    }

    let mut result = db
        .query("SELECT * FROM social_group")
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query groups: {}", e)))?;
    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse groups: {}", e)))?;

    let mut visible_groups = Vec::new();
    for group in groups.into_iter().filter(|group| {
        let group_id = group
            .id
            .as_ref()
            .map(|thing| normalize_group_id(&thing_key_string(thing)))
            .unwrap_or_default();
        group.owner_id == current_user_id || group_ids.contains(&group_id)
    }) {
        visible_groups.push(hydrate_social_group(&db, group).await?);
    }

    Ok(Json(visible_groups))
}

async fn add_group_members(
    claims: Claims,
    Path(group_id): Path<String>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<AddGroupMembersRequest>,
) -> Result<Json<SocialGroup>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_admin_access(&db, &current_user_id, &group_id).await?;

    let mut new_member_ids = normalize_unique_ids(req.member_ids);
    new_member_ids.retain(|member_id| !group.member_user_ids.contains(member_id));
    if new_member_ids.is_empty() {
        return Ok(Json(group));
    }

    for member_id in &new_member_ids {
        let _ = ensure_user_exists(&db, member_id).await?;
        if !friendship_exists(&db, &current_user_id, member_id).await? {
            return Err(AuthError::Forbidden("You can only add friends to a human group".to_string()));
        }
    }

    create_social_group_members(&db, &group_id, &new_member_ids, &Vec::new(), &chrono::Utc::now().to_rfc3339()).await?;

    let updated = hydrate_social_group(
        &db,
        ensure_group_access(&db, &current_user_id, &group_id).await?,
    )
    .await?;

    publish_group_updated(&social_hub, &group_id, &updated.member_user_ids).await;

    Ok(Json(updated))
}

async fn update_group_admin(
    claims: Claims,
    Path(group_id): Path<String>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<UpdateGroupAdminRequest>,
) -> Result<Json<SocialGroup>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_access(&db, &current_user_id, &group_id).await?;
    if group.group_type != 2 {
        return Err(AuthError::BadRequest(
            "This management action is currently only enabled for scenario 2".to_string(),
        ));
    }
    if group.owner_id != current_user_id {
        return Err(AuthError::Forbidden("Only the group owner can manage admins".to_string()));
    }

    let target_user_id = normalize_user_id(&req.target_user_id);
    if target_user_id == group.owner_id {
        return Err(AuthError::BadRequest("Group owner cannot be set as admin".to_string()));
    }
    if !group.member_user_ids.contains(&target_user_id) {
        return Err(AuthError::NotFound("Target member is not in this group".to_string()));
    }

    let mut admin_ids = group.admin_ids.clone();
    if req.is_admin {
        if !admin_ids.contains(&target_user_id) {
            admin_ids.push(target_user_id.clone());
        }
    } else {
        admin_ids.retain(|id| id != &target_user_id);
    }

    let mut result = db
        .query("UPDATE type::record('social_group', $group_id) SET admin_ids = $admin_ids RETURN AFTER")
        .bind(("group_id", group_id.clone()))
        .bind(("admin_ids", admin_ids))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to update social_group admins: {}", e)))?;
    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse updated social_group: {}", e)))?;
    let updated = groups
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::NotFound("Group not found".to_string()))?;
    let updated = hydrate_social_group(&db, updated).await?;

    publish_group_updated(&social_hub, &group_id, &updated.member_user_ids).await;
    Ok(Json(updated))
}

async fn remove_group_member(
    claims: Claims,
    Path((group_id, member_id)): Path<(String, String)>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
) -> Result<Json<SocialGroup>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_admin_access(&db, &current_user_id, &group_id).await?;
    let target_user_id = normalize_user_id(&member_id);
    if target_user_id == group.owner_id {
        return Err(AuthError::Forbidden("The group owner cannot be removed".to_string()));
    }
    if !group.member_user_ids.contains(&target_user_id) {
        return Err(AuthError::NotFound("Target member is not in this group".to_string()));
    }

    let operator_is_owner = group.owner_id == current_user_id;
    let target_is_admin = group.admin_ids.contains(&target_user_id);
    if !operator_is_owner && target_is_admin {
        return Err(AuthError::Forbidden("Admins cannot remove other admins".to_string()));
    }

    let new_admin_ids: Vec<String> = group
        .admin_ids
        .iter()
        .filter(|id| *id != &target_user_id)
        .cloned()
        .collect();
    let _ = db
        .query("UPDATE type::record('social_group', $group_id) SET admin_ids = $admin_ids")
        .bind(("group_id", group_id.clone()))
        .bind(("admin_ids", new_admin_ids))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to update social_group admins: {}", e)))?;

    remove_social_group_member(&db, &group_id, &target_user_id).await?;

    let updated = load_group_by_id(&db, &group_id).await?;
    publish_group_updated(&social_hub, &group_id, &updated.member_user_ids).await;
    let _ = social_hub
        .publish(
            &target_user_id,
            &SocialEvent::GroupDeleted {
                group_id: group_id.clone(),
            },
        )
        .await;

    Ok(Json(updated))
}

async fn transfer_group_ownership(
    claims: Claims,
    Path(group_id): Path<String>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<TransferGroupOwnershipRequest>,
) -> Result<Json<SocialGroup>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_access(&db, &current_user_id, &group_id).await?;
    if group.group_type != 2 {
        return Err(AuthError::BadRequest(
            "This management action is currently only enabled for scenario 2".to_string(),
        ));
    }
    if group.owner_id != current_user_id {
        return Err(AuthError::Forbidden("Only the group owner can transfer ownership".to_string()));
    }

    let new_owner_id = normalize_user_id(&req.new_owner_id);
    if new_owner_id == current_user_id {
        return Err(AuthError::BadRequest("Target user is already the group owner".to_string()));
    }
    if !group.member_user_ids.contains(&new_owner_id) {
        return Err(AuthError::NotFound("New owner must be a current group member".to_string()));
    }

    let mut admin_ids: Vec<String> = group
        .admin_ids
        .iter()
        .filter(|id| *id != &new_owner_id)
        .cloned()
        .collect();
    if !admin_ids.contains(&current_user_id) {
        admin_ids.push(current_user_id.clone());
    }

    let mut result = db
        .query(
            "UPDATE type::record('social_group', $group_id)
             SET ownerId = $new_owner_id, admin_ids = $admin_ids
             RETURN AFTER",
        )
        .bind(("group_id", group_id.clone()))
        .bind(("new_owner_id", new_owner_id))
        .bind(("admin_ids", admin_ids))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to transfer group ownership: {}", e)))?;
    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse updated social_group: {}", e)))?;
    let updated = groups
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::NotFound("Group not found".to_string()))?;
    let updated = hydrate_social_group(&db, updated).await?;

    publish_group_updated(&social_hub, &group_id, &updated.member_user_ids).await;
    Ok(Json(updated))
}

async fn leave_group(
    claims: Claims,
    Path(group_id): Path<String>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
) -> Result<Json<serde_json::Value>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_access(&db, &current_user_id, &group_id).await?;
    if group.group_type != 2 {
        return Err(AuthError::BadRequest(
            "This management action is currently only enabled for scenario 2".to_string(),
        ));
    }
    if group.owner_id == current_user_id {
        return Err(AuthError::Forbidden("The group owner must transfer ownership or dissolve the group".to_string()));
    }

    let new_admin_ids: Vec<String> = group
        .admin_ids
        .iter()
        .filter(|id| *id != &current_user_id)
        .cloned()
        .collect();
    let _ = db
        .query("UPDATE type::record('social_group', $group_id) SET admin_ids = $admin_ids")
        .bind(("group_id", group_id.clone()))
        .bind(("admin_ids", new_admin_ids))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to update social_group admins: {}", e)))?;
    remove_social_group_member(&db, &group_id, &current_user_id).await?;

    let updated = load_group_by_id(&db, &group_id).await?;
    publish_group_updated(&social_hub, &group_id, &updated.member_user_ids).await;
    let _ = social_hub
        .publish(
            &current_user_id,
            &SocialEvent::GroupDeleted {
                group_id: group_id.clone(),
            },
        )
        .await;

    Ok(Json(json!({ "success": true })))
}

async fn update_group_settings(
    claims: Claims,
    Path(group_id): Path<String>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<UpdateGroupSettingsRequest>,
) -> Result<Json<SocialGroup>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_admin_access(&db, &current_user_id, &group_id).await?;
    let join_mode = req.join_mode.trim();
    if join_mode.is_empty() {
        return Err(AuthError::ValidationError("join_mode is required".to_string()));
    }

    let settings = GroupSettings {
        join_mode: join_mode.to_string(),
        allow_member_invite: req.allow_member_invite,
        allow_file_upload: req.allow_file_upload,
    };

    let mut result = db
        .query("UPDATE type::record('social_group', $group_id) SET settings = $settings RETURN AFTER")
        .bind(("group_id", group_id.clone()))
        .bind(("settings", settings))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to update social_group settings: {}", e)))?;
    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse updated social_group: {}", e)))?;
    let updated = groups
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::NotFound("Group not found".to_string()))?;
    let updated = hydrate_social_group(&db, updated).await?;

    for member_id in updated.member_user_ids.iter() {
        let _ = social_hub
            .publish(
                member_id,
                &SocialEvent::GroupUpdated {
                    group_id: group_id.clone(),
                },
            )
            .await;
    }

    Ok(Json(updated))
}

async fn update_group_announcement(
    claims: Claims,
    Path(group_id): Path<String>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<UpdateGroupAnnouncementRequest>,
) -> Result<Json<SocialGroup>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let _group = ensure_group_admin_access(&db, &current_user_id, &group_id).await?;
    let announcement = req.announcement.trim().to_string();

    let mut result = db
        .query("UPDATE type::record('social_group', $group_id) SET announcement = $announcement RETURN AFTER")
        .bind(("group_id", group_id.clone()))
        .bind(("announcement", Some(announcement)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to update social_group announcement: {}", e)))?;
    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse updated social_group: {}", e)))?;
    let updated = groups
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::NotFound("Group not found".to_string()))?;
    let updated = hydrate_social_group(&db, updated).await?;

    for member_id in updated.member_user_ids.iter() {
        let _ = social_hub
            .publish(
                member_id,
                &SocialEvent::GroupUpdated {
                    group_id: group_id.clone(),
                },
            )
            .await;
    }

    Ok(Json(updated))
}

async fn dissolve_group(
    claims: Claims,
    Path(group_id): Path<String>,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
) -> Result<Json<serde_json::Value>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let group = ensure_group_access(&db, &current_user_id, &group_id).await?;
    if group.owner_id != current_user_id {
        return Err(AuthError::Forbidden("Only the group owner can dissolve the group".to_string()));
    }

    let member_ids = group.member_user_ids.clone();
    let _ = db
        .query("DELETE social_group_member WHERE group_id = $group_id")
        .bind(("group_id", group_id.clone()))
        .await;
    let _ = db
        .query("DELETE group_thread_message WHERE group_id = $group_id")
        .bind(("group_id", group_id.clone()))
        .await;
    let _ = db
        .query("DELETE group_collab_run WHERE group_id = $group_id")
        .bind(("group_id", group_id.clone()))
        .await;
    let _ = db
        .query("DELETE group_thread WHERE group_id = $group_id")
        .bind(("group_id", group_id.clone()))
        .await;
    let _ = db
        .query("DELETE type::record('social_group', $group_id)")
        .bind(("group_id", group_id.clone()))
        .await;

    for member_id in member_ids.iter() {
        let _ = social_hub
            .publish(
                member_id,
                &SocialEvent::GroupDeleted {
                    group_id: group_id.clone(),
                },
            )
            .await;
    }

    Ok(Json(json!({ "success": true })))
}

async fn create_group(
    claims: Claims,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<SocialGroup>> {
    let owner_id = normalize_user_id(&claims.sub);
    let name = req.name.trim();
    if name.is_empty() {
        return Err(AuthError::ValidationError("Group name is required".to_string()));
    }
    if !matches!(req.group_type, 2 | 6 | 9) {
        return Err(AuthError::ValidationError("Unsupported group type".to_string()));
    }

    let level = req.level.unwrap_or_else(|| "RED".to_string());
    let member_ids = normalize_unique_ids(req.member_ids);
    let human_member_ids = normalize_unique_ids(req.human_member_ids);
    let ai_member_ids = req.ai_member_ids;

    for member_id in member_ids.iter().chain(human_member_ids.iter()) {
        let _ = ensure_user_exists(&db, member_id).await?;
        if member_id != &owner_id && !friendship_exists(&db, &owner_id, member_id).await? {
            return Err(AuthError::Forbidden("You can only add friends to a group".to_string()));
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let member_user_ids = match req.group_type {
        2 => {
            let mut items = vec![owner_id.clone()];
            items.extend(member_ids.clone());
            normalize_unique_ids(items)
        }
        6 | 9 => {
            let mut items = vec![owner_id.clone()];
            items.extend(human_member_ids.clone());
            normalize_unique_ids(items)
        }
        _ => vec![owner_id.clone()],
    };

    let (announcement, settings, code, description, max_humans, max_ais, member_ids, human_member_ids) =
        match req.group_type {
            2 => (
                Some(String::new()),
                Some(GroupSettings {
                    join_mode: "ADMIN_APPROVAL".to_string(),
                    allow_member_invite: true,
                    allow_file_upload: true,
                }),
                Some(generate_group_code()),
                None,
                None,
                None,
                member_user_ids.clone(),
                member_user_ids.clone(),
            ),
            6 => (
                None,
                None,
                None,
                Some(String::new()),
                None,
                None,
                Vec::new(),
                vec![owner_id.clone()],
            ),
            9 => {
                let (max_humans, max_ais) = match level.as_str() {
                    "RED" => (18, 5),
                    "ORANGE" => (45, 10),
                    "YELLOW" => (90, 20),
                    _ => (18, 5),
                };
                (
                    None,
                    None,
                    Some(generate_group_code()),
                    Some(String::new()),
                    Some(max_humans),
                    Some(max_ais),
                    Vec::new(),
                    member_user_ids.clone(),
                )
            }
            _ => unreachable!(),
        };

    let group = SocialGroup {
        id: Some(Thing::new("social_group", Uuid::new_v4().to_string())),
        name: name.to_string(),
        avatar: default_group_avatar(req.group_type).to_string(),
        group_type: req.group_type,
        level,
        owner_id,
        created_at: now,
        admin_ids: Vec::new(),
        member_ids,
        announcement,
        settings,
        code,
        human_member_ids,
        ai_member_ids,
        description,
        max_humans,
        max_ais,
        member_user_ids,
    };

    let mut created = create_social_group_record(&db, &group).await.map_err(|e| {
        tracing::error!("create_group failed while creating social_group record: {}", e);
        e
    })?;

    let created_group_id = created
        .id
        .as_ref()
        .map(|thing| normalize_group_id(&thing_key_string(thing)))
        .ok_or_else(|| AuthError::DatabaseError("Created social_group missing id".to_string()))?;

    create_social_group_members(
        &db,
        &created_group_id,
        &group.member_user_ids,
        &group.ai_member_ids,
        &group.created_at,
    )
    .await
    .map_err(|e| {
        tracing::error!("create_group failed while creating social_group_member rows for {}: {}", created_group_id, e);
        e
    })?;

    let needs_repair = created.member_ids != group.member_ids
        || created.human_member_ids != group.human_member_ids
        || created.member_user_ids != group.member_user_ids;

    if needs_repair {
        tracing::warn!(
            "social_group persisted with unexpected member fields, repairing. expected={:?}, actual={:?}",
            group,
            created
        );
        created = persist_social_group_members(
            &db,
            &created_group_id,
            &group.member_ids,
            &group.human_member_ids,
            &group.member_user_ids,
        )
        .await
        .map_err(|e| {
            tracing::error!("create_group failed while repairing social_group member fields for {}: {}", created_group_id, e);
            e
        })?;
    }

    if group_supports_threads(created.group_type) {
        let _ = create_default_group_thread(&db, &created_group_id, &created.owner_id)
            .await
            .map_err(|e| {
                tracing::error!("create_group failed while creating default thread for {}: {}", created_group_id, e);
                e
            })?;
    }

    created = hydrate_social_group(&db, created).await.map_err(|e| {
        tracing::error!("create_group failed while hydrating social_group {}: {}", created_group_id, e);
        e
    })?;
    for member_id in created.member_user_ids.iter() {
        let _ = social_hub
            .publish(
                member_id,
                &SocialEvent::GroupCreated {
                    group_id: created_group_id.clone(),
                },
            )
            .await;
    }
    tracing::info!("Created social_group persisted as: {:?}", created);
    Ok(Json(created))
}

async fn list_direct_conversations(
    claims: Claims,
    State(db): State<Arc<Database>>,
) -> Result<Json<Vec<DirectConversationView>>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let query = r#"
        SELECT * FROM direct_conversation
        WHERE <string>user_a = $user_id OR <string>user_b = $user_id
        ORDER BY updated_at DESC
    "#;
    let mut result = db
        .query(query)
        .bind(("user_id", surreal_user_id_string(&current_user_id)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query direct conversations: {}", e)))?;
    let conversations: Vec<DirectConversation> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse direct conversations: {}", e)))?;

    let mut views = Vec::with_capacity(conversations.len());
    for conversation in conversations {
        views.push(direct_conversation_view_for(&db, &current_user_id, conversation).await?);
    }
    Ok(Json(views))
}

async fn ensure_direct_conversation_route(
    claims: Claims,
    State(db): State<Arc<Database>>,
    Json(req): Json<EnsureDirectConversationRequest>,
) -> Result<Json<DirectConversationView>> {
    let requester_id = normalize_user_id(&claims.sub);
    let target_user_id = normalize_user_id(&req.target_user_id);
    if requester_id == target_user_id {
        return Err(AuthError::ValidationError("Cannot chat with yourself".to_string()));
    }
    let conversation = ensure_direct_conversation(&db, &requester_id, &target_user_id).await?;
    let view = direct_conversation_view_for(&db, &requester_id, conversation).await?;
    Ok(Json(view))
}

async fn list_direct_messages(
    claims: Claims,
    State(db): State<Arc<Database>>,
    axum::extract::Path(conversation_id): axum::extract::Path<String>,
) -> Result<Json<Vec<DirectMessageView>>> {
    let current_user_id = normalize_user_id(&claims.sub);
    let mut conversation_query = db
        .query("SELECT * FROM direct_conversation WHERE <string>id = $conversation_id LIMIT 1")
        .bind(("conversation_id", surreal_direct_conversation_id_string(&conversation_id)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query direct conversation: {}", e)))?;
    let items: Vec<DirectConversation> = conversation_query
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse direct conversation: {}", e)))?;
    let conversation = items
        .into_iter()
        .next()
        .ok_or_else(|| AuthError::NotFound("Conversation not found".to_string()))?;
    let left_id = normalize_user_id(&thing_key_string(&conversation.user_a));
    let right_id = normalize_user_id(&thing_key_string(&conversation.user_b));
    if left_id != current_user_id && right_id != current_user_id {
        return Err(AuthError::Forbidden("You are not part of this conversation".to_string()));
    }

    let query = r#"
        SELECT * FROM direct_message
        WHERE <string>conversation_id = $conversation_id
        ORDER BY created_at ASC
        LIMIT 200
    "#;
    let mut result = db
        .query(query)
        .bind(("conversation_id", surreal_direct_conversation_id_string(&conversation_id)))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query direct messages: {}", e)))?;
    let messages: Vec<DirectMessage> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse direct messages: {}", e)))?;
    Ok(Json(messages.into_iter().map(map_direct_message_view).collect()))
}

async fn send_direct_message(
    claims: Claims,
    State(db): State<Arc<Database>>,
    Extension(social_hub): Extension<Arc<SocialHub>>,
    Json(req): Json<SendDirectMessageRequest>,
) -> Result<Json<DirectMessageView>> {
    let sender_id = normalize_user_id(&claims.sub);
    let target_user_id = normalize_user_id(&req.target_user_id);
    let content = req.content.trim();
    if content.is_empty() {
        return Err(AuthError::ValidationError("Message content is required".to_string()));
    }

    let conversation = ensure_direct_conversation(&db, &sender_id, &target_user_id).await?;
    let conversation_id = conversation
        .id
        .as_ref()
        .map(thing_key_string)
        .unwrap_or_default();

    let now = chrono::Utc::now().timestamp();
    let message = DirectMessage {
        id: Some(direct_message_thing(&Uuid::new_v4().to_string())),
        conversation_id: direct_conversation_thing(&conversation_id),
        sender_id: user_thing(&sender_id),
        recipient_id: user_thing(&target_user_id),
        content: content.to_string(),
        created_at: now,
    };
    let created: DirectMessage = db.create_record("direct_message", &message).await?;

    let mut update_result = db
        .query("UPDATE $conversation_id SET updated_at = $updated_at")
        .bind(("conversation_id", direct_conversation_thing(&conversation_id)))
        .bind(("updated_at", now))
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to update conversation timestamp: {}", e)))?;
    let _updated: Vec<DirectConversation> = update_result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse updated conversation: {}", e)))?;

    let view = map_direct_message_view(created);
    let message_id = view.id.clone();
    let _ = social_hub
        .publish(
            &target_user_id,
            &SocialEvent::DirectMessageCreated {
                conversation_id: conversation_id.clone(),
                message_id: message_id.clone(),
                sender_id: sender_id.clone(),
            },
        )
        .await;
    let _ = social_hub
        .publish(
            &sender_id,
            &SocialEvent::DirectMessageCreated {
                conversation_id,
                message_id,
                sender_id: sender_id.clone(),
            },
        )
        .await;

    Ok(Json(view))
}

// Google 登录
async fn google_login(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<axum::response::Redirect> {
    let auth_service = AuthService::new(db, config)?;
    let auth_url = auth_service.get_google_auth_url()?;
    Ok(axum::response::Redirect::to(&auth_url))
}

// Google 回调处理
async fn google_callback(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Query(params): Query<OAuthCallback>,
) -> Result<axum::response::Response> {
    tracing::info!("Starting Google OAuth callback");
    let auth_service = AuthService::new(db, config)?;
    let auth_response = match auth_service.handle_google_callback(params.code).await {
        Ok(response) => response,
        Err(e) => {
            error!("Google callback failed: {:?}", e);
            return Err(e);
        }
    };
    
    // 检查用户是否有密码
    let redirect_url = if !auth_response.user.has_password {
        // 重定向到设置密码页面，并传递 token
        format!("http://129.226.169.63:4173/initialize-password?token={}", auth_response.token)
    } else {
        // 正常重定向到OAuth回调页面，并传递 token
        format!("http://129.226.169.63:4173/oauth/callback?token={}", auth_response.token)
    };

    tracing::info!("OAuth callback completed, redirecting user");
    Ok(axum::response::Redirect::to(&redirect_url).into_response())
}

// GitHub 登录
async fn github_login(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<axum::response::Redirect> {
    let auth_service = AuthService::new(db, config)?;
    let auth_url = auth_service.get_github_auth_url()?;
    Ok(axum::response::Redirect::to(&auth_url))
}

// GitHub 回调处理
async fn github_callback(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Query(params): Query<OAuthCallback>,
) -> Result<axum::response::Response> {
    let auth_service = AuthService::new(db, config)?;
    let auth_response = auth_service.handle_github_callback(params.code).await?;
    
    // 检查用户是否有密码
    let redirect_url = if !auth_response.user.has_password {
        // 重定向到设置密码页面，并传递 token
        format!("http://localhost:5173/initialize-password?token={}", auth_response.token)
    } else {
        // 正常重定向到OAuth回调页面，并传递 token
        format!("http://localhost:5173/oauth/callback?token={}", auth_response.token)
    };

    Ok(axum::response::Redirect::to(&redirect_url).into_response())
}

// 初始化密码处理函数
async fn initialize_password(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Json(request): Json<InitializePasswordRequest>,
) -> Result<Json<UserResponse>> {
    let auth_service = AuthService::new(db, config)?;
    let user = auth_service.initialize_password(&claims.sub, &request.password).await?;
    Ok(Json(user.into()))
}

// 请求密码重置处理函数
async fn request_password_reset(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<RequestPasswordResetRequest>,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.request_password_reset(request.email).await?;
    Ok("Password reset email sent if account exists")
}

// 重置密码处理函数
async fn reset_password(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<ResetPasswordRequest>,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.reset_password(request.token, request.new_password).await?;
    Ok("Password reset successfully")
}

// 登出处理函数
async fn logout(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    claims: Claims,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.logout(bearer.token().to_string()).await?;
    Ok("Logged out successfully")
}

// 登出所有会话处理函数
async fn logout_all(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.logout_all_sessions(&claims.sub).await?;
    Ok("All sessions logged out successfully")
}

// 获取用户会话列表处理函数
async fn get_sessions(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    claims: Claims,
) -> Result<Json<Vec<SessionInfo>>> {
    let auth_service = AuthService::new(db, config)?;
    let sessions = auth_service.get_user_sessions(&claims.sub, bearer.token()).await?;
    Ok(Json(sessions))
}

// 错误处理中间件
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        if matches!(
            self,
            AuthError::DatabaseError(_) | AuthError::ServerError(_) | AuthError::InternalServerError(_)
        ) {
            tracing::error!("AuthError response: {}", self);
        }
        let (status, message) = match &self {
            AuthError::DatabaseError(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AuthError::InvalidCredentials => (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid credentials".to_string(),
            ),
            AuthError::EmailNotVerified => (
                axum::http::StatusCode::FORBIDDEN,
                "Email not verified".to_string(),
            ),
            AuthError::TokenError(_) => (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid token".to_string(),
            ),
            AuthError::UserNotFound => (
                axum::http::StatusCode::NOT_FOUND,
                "User not found".to_string(),
            ),
            AuthError::EmailExists => (
                axum::http::StatusCode::CONFLICT,
                "Email already exists".to_string(),
            ),
            AuthError::UsernameExists => (
                axum::http::StatusCode::CONFLICT,
                "Username already exists".to_string(),
            ),
            AuthError::InvalidToken => (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid token".to_string(),
            ),
            AuthError::ServerError(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AuthError::OAuthError(_) => (
                axum::http::StatusCode::BAD_REQUEST,
                "OAuth error".to_string(),
            ),
            AuthError::PasswordAlreadySet => (
                axum::http::StatusCode::CONFLICT,
                "Password already set".to_string(),
            ),
            AuthError::InvalidUserId => (
                axum::http::StatusCode::BAD_REQUEST,
                "Invalid user ID".to_string(),
            ),
            AuthError::NotFound(msg) => (
                axum::http::StatusCode::NOT_FOUND,
                msg.clone(),
            ),
            AuthError::ValidationError(msg) => (
                axum::http::StatusCode::BAD_REQUEST,
                msg.clone(),
            ),
            AuthError::PermissionDenied => (
                axum::http::StatusCode::FORBIDDEN,
                "Permission denied".to_string(),
            ),
            AuthError::InsufficientPermissions => (
                axum::http::StatusCode::FORBIDDEN,
                "Insufficient permissions".to_string(),
            ),
            AuthError::AccountSuspended => (
                axum::http::StatusCode::FORBIDDEN,
                "Account suspended".to_string(),
            ),
            AuthError::AccountInactive => (
                axum::http::StatusCode::FORBIDDEN,
                "Account inactive".to_string(),
            ),
            AuthError::AccountDeleted => (
                axum::http::StatusCode::FORBIDDEN,
                "Account deleted".to_string(),
            ),
            AuthError::Forbidden(msg) => (
                axum::http::StatusCode::FORBIDDEN,
                msg.clone(),
            ),
            AuthError::BadRequest(msg) => (
                axum::http::StatusCode::BAD_REQUEST,
                msg.clone(),
            ),
            AuthError::Unauthorized(msg) => (
                axum::http::StatusCode::UNAUTHORIZED,
                msg.clone(),
            ),
            AuthError::InternalServerError(msg) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
            ),
        };

        let body = Json(serde_json::json!({
            "error": message
        }));

        (status, body).into_response()
    }
}
