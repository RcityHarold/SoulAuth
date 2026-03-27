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
    models::group::{CreateGroupRequest, GroupSettings, SocialGroup},
    models::user::{CreateUserRequest, LoginRequest, AuthResponse, User, UserResponse, InitializePasswordRequest},
    models::password_reset::{RequestPasswordResetRequest, ResetPasswordRequest},
    models::session::{LogoutRequest, SessionInfo},
    services::auth::AuthService,
    services::social_hub::{SocialEvent, SocialHub},
    utils::jwt::{decode_token_claims, Claims},
};
use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, Query, State, TypedHeader, ConnectInfo},
    headers::{authorization::Bearer, Authorization},
    routing::{get, post},
    Json, Router,
    Extension,
    response::IntoResponse,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use std::{sync::Arc, net::SocketAddr};
use crate::{services::database::Database, utils::rate_limit_middleware::check_rate_limit_for_request, AppState};
use tracing::{error, info};
use serde_json::json;
use surrealdb::sql::Thing;
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
    let ip_lockout_result = app_state.lockout_service.check_ip_lockout(&client_ip).await.map_err(|e| {
        error!("Failed to check IP lockout: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Internal server error",
            "message": "Service unavailable"
        })))
    })?;
    
    if ip_lockout_result.is_locked {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(json!({
            "error": "Account locked",
            "message": ip_lockout_result.message,
            "locked_until_seconds": ip_lockout_result.remaining_lockout_seconds
        }))));
    }
    
    // 检查用户账户锁定（如果我们能找到用户）
    // 注意：为了防止用户枚举攻击，我们需要小心处理这个检查
    let user_lockout_result = app_state.lockout_service.check_user_lockout(&req.email).await.map_err(|e| {
        error!("Failed to check user lockout: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Internal server error",
            "message": "Service unavailable"
        })))
    })?;
    
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
    Thing::from((String::from("user"), normalize_user_id(user_id)))
}

fn request_thing(request_id: &str) -> Thing {
    Thing::from((String::from("friend_request"), normalize_request_id(request_id)))
}

fn direct_conversation_thing(conversation_id: &str) -> Thing {
    Thing::from((
        String::from("direct_conversation"),
        normalize_direct_conversation_id(conversation_id),
    ))
}

fn direct_message_thing(message_id: &str) -> Thing {
    Thing::from((String::from("direct_message"), message_id.trim().to_string()))
}

fn surreal_user_id_string(user_id: &str) -> String {
    format!("user:⟨{}⟩", normalize_user_id(user_id))
}

fn surreal_request_id_string(request_id: &str) -> String {
    format!("friend_request:⟨{}⟩", normalize_request_id(request_id))
}

fn surreal_direct_conversation_id_string(conversation_id: &str) -> String {
    format!(
        "direct_conversation:⟨{}⟩",
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
        id: Some(Thing::from((
            String::from("direct_conversation"),
            Uuid::new_v4().to_string(),
        ))),
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
        .map(|value| value.id.to_string())
        .unwrap_or_default();
    let left_id = normalize_user_id(&conversation.user_a.id.to_string());
    let right_id = normalize_user_id(&conversation.user_b.id.to_string());
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
            .map(|value| value.id.to_string())
            .unwrap_or_default(),
        conversation_id: normalize_direct_conversation_id(&message.conversation_id.id.to_string()),
        sender_id: normalize_user_id(&message.sender_id.id.to_string()),
        recipient_id: normalize_user_id(&message.recipient_id.id.to_string()),
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
    let requester_id = normalize_user_id(&request.requester_id.id.to_string());
    let addressee_id = normalize_user_id(&request.addressee_id.id.to_string());
    let requester = ensure_user_exists(db, &requester_id).await?;
    let addressee = ensure_user_exists(db, &addressee_id).await?;

    Ok(FriendRequestView {
        request_id: request
            .id
            .as_ref()
            .map(|value| value.id.to_string())
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
        id: Some(Thing::from((String::from("friend_request"), request_id.clone()))),
        requester_id: user_thing(&requester_id),
        addressee_id: user_thing(&target_user_id),
        status: FriendRequestStatus::Pending,
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
        status: FriendRequestStatus::Pending,
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

    if normalize_user_id(&request.addressee_id.id.to_string()) != current_user_id {
        return Err(AuthError::Forbidden("You can only respond to your own incoming requests".to_string()));
    }
    if request.status != FriendRequestStatus::Pending {
        return Err(AuthError::ValidationError("This friend request has already been processed".to_string()));
    }

    let new_status = if req.accept {
        FriendRequestStatus::Accepted
    } else {
        FriendRequestStatus::Rejected
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
        let requester_id = normalize_user_id(&request.requester_id.id.to_string());
        let addressee_id = normalize_user_id(&request.addressee_id.id.to_string());
        if !friendship_exists(&db, &requester_id, &addressee_id).await? {
            let (a, b) = canonical_friend_pair(&requester_id, &addressee_id);
            let friendship = Friendship {
                id: Some(Thing::from((String::from("friendship"), Uuid::new_v4().to_string()))),
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
        let requester_id = normalize_user_id(&request.requester_id.id.to_string());
        let addressee_id = normalize_user_id(&request.addressee_id.id.to_string());
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
        let left_id = normalize_user_id(&friendship.user_a.id.to_string());
        let right_id = normalize_user_id(&friendship.user_b.id.to_string());
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
    let mut result = db
        .query("SELECT * FROM social_group")
        .await
        .map_err(|e| AuthError::DatabaseError(format!("Failed to query groups: {}", e)))?;
    let groups: Vec<SocialGroup> = result
        .take(0)
        .map_err(|e| AuthError::DatabaseError(format!("Failed to parse groups: {}", e)))?;

    Ok(Json(
        groups
            .into_iter()
            .filter(|group| {
                group.owner_id == current_user_id
                    || group.member_ids.contains(&current_user_id)
                    || group.human_member_ids.contains(&current_user_id)
                    || group.member_user_ids.contains(&current_user_id)
            })
            .collect(),
    ))
}

async fn create_group(
    claims: Claims,
    State(db): State<Arc<Database>>,
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
        id: Some(Thing::from((String::from("social_group"), Uuid::new_v4().to_string()))),
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

    let mut created: SocialGroup = db.create_record("social_group", &group).await?;

    let needs_repair = created.member_ids != group.member_ids
        || created.human_member_ids != group.human_member_ids
        || created.member_user_ids != group.member_user_ids;

    if needs_repair {
        tracing::warn!(
            "social_group persisted with unexpected member fields, repairing. expected={:?}, actual={:?}",
            group,
            created
        );
        if let Some(ref thing) = created.id {
            created = db.update_record("social_group", thing, &group).await?;
        }
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
    let left_id = normalize_user_id(&conversation.user_a.id.to_string());
    let right_id = normalize_user_id(&conversation.user_b.id.to_string());
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
        .map(|value| value.id.to_string())
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
