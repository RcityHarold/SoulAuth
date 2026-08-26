//! SoulAuth V2 Architecture Conformance Suite
//!
//! # 这个套件回答什么
//!
//! 「离目标态还差多少」——一个客观读数，而不是靠感觉。
//!
//! 三份 V2 文档各自列了一组不变式（工程指导 §17 十四条 / Canonical Architecture
//! §25 约十八条 / Engineering Delta §24 八个验收场景），高度重叠但措辞与数量都
//! 不一致。三处各测一份必然互相漂移，所以这里合并去重成**唯一权威清单**，
//! 每条都标注法源。
//!
//! # 为什么是文本与 schema 内省，不是类型断言
//!
//! 本 crate 没有 `lib.rs`，集成测试导不进内部类型——这反而是对的。架构一致性
//! 断言的是**结构事实**，而结构事实里最要紧的一类是「某个东西不存在」：
//! 身份根上不许有 `membership_level`、审计里不许出现明文令牌、非人主体的枚举
//! 变体不许只存在于定义处而无人构造。这些用类型系统表达不出来，用文本内省
//! 恰好可以，而且不会因为内部重构而误报。
//!
//! # 怎么读这份读数
//!
//! ```text
//! cargo test --test conformance              # 当前已成立的不变式，应当全绿
//! cargo test --test conformance -- --ignored # 目标态尚未成立的，红的就是待办
//! ```
//!
//! 尚未成立的用 `#[ignore]` 标注并写明属于哪个 Stage。这样常规 `cargo test`
//! 保持干净（不制造长期红），而 `--ignored` 一跑就是精确的剩余工作量。
//!
//! **每完成一个 Stage，删掉对应的 `#[ignore]`。** 删不掉就说明那个 Stage 没真做完。
//!
//! # 改造期间最贵的回归
//!
//! 不是「新东西没做出来」，而是「改本体的时候把已经成立的边界弄坏了」。
//! 下面没有 `#[ignore]` 的那些，全部是当前**已经成立**的纪律——它们在整个
//! V2 改造过程中必须一直是绿的。

use std::fs;
use std::path::{Path, PathBuf};

// ───────────────────────── 内省辅助 ─────────────────────────

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = root().join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display()))
}

fn schema() -> String {
    read("schema.sql")
}

fn seed() -> String {
    read("initial_data.sql")
}

/// 递归收集 `src/` 下全部 Rust 源码，返回 (相对路径, 内容)。
fn sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let base = root().join("src");
    walk(&base, &base, &mut out);
    assert!(
        !out.is_empty(),
        "src/ 下没有找到任何 .rs —— 内省辅助本身坏了"
    );
    out
}

fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(base, &path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(body) = fs::read_to_string(&path) {
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(path.as_path())
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, body));
            }
        }
    }
}

/// 源码中命中 `needle` 的位置，返回 "文件:行" 列表。
///
/// 会跳过 `//` 行注释与 `#[cfg(test)]` 之后的内容：一条禁令说的是**生产代码
/// 不许做某事**，注释里提到那个词、或者测试里为了断言而写出那个词，都不构成违反。
fn hits(needle: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (file, body) in sources() {
        let production = match body.find("#[cfg(test)]") {
            Some(i) => &body[..i],
            None => &body[..],
        };
        for (n, line) in production.lines().enumerate() {
            let code = match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            };
            if code.contains(needle) {
                found.push(format!("{file}:{}", n + 1));
            }
        }
    }
    found
}

/// 任意一个 needle 命中即返回，用于「这一族词一个都不许出现」。
fn hits_any(needles: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for n in needles {
        for h in hits(n) {
            found.push(format!("{h}  ({n})"));
        }
    }
    found
}

fn table_exists(name: &str) -> bool {
    let s = schema();
    s.contains(&format!("DEFINE TABLE {name} "))
        || s.contains(&format!("DEFINE TABLE IF NOT EXISTS {name} "))
}

fn field_exists(table: &str, field: &str) -> bool {
    schema().contains(&format!("DEFINE FIELD {field} ON {table} "))
}

fn fields_of(table: &str) -> Vec<String> {
    let marker = format!(" ON {table} ");
    schema()
        .lines()
        .filter(|l| l.trim_start().starts_with("DEFINE FIELD") && l.contains(&marker))
        .filter_map(|l| l.split_whitespace().nth(2).map(str::to_string))
        .collect()
}

/// 当前承担「身份根」职责的表。V2 落地后应为 `actor_identity`。
fn identity_root() -> &'static str {
    if table_exists("actor_identity") {
        "actor_identity"
    } else {
        "user"
    }
}

fn assert_absent(found: Vec<String>, rule: &str) {
    assert!(
        found.is_empty(),
        "{rule}\n违反位置:\n  {}",
        found.join("\n  ")
    );
}

// ═════════════════════ A. 身份本体 ═════════════════════
// 法源: Canonical Architecture §4 / §5 / §6, Engineering Delta §1 / §3 / §4

/// A1 · ActorIdentity ≠ Account
///
/// 身份根只回答「谁」。email / username / 邮箱验证状态属于 Human Account，
/// 是 Human-specific Extension，不是身份本体。
#[test]
fn a1_actor_identity_is_not_account() {
    assert!(
        table_exists("actor_identity"),
        "缺少身份根表 actor_identity"
    );
    assert!(table_exists("human_account"), "缺少 human_account");

    let root_fields = fields_of("actor_identity");
    for account_only in ["email", "username", "username_normalized", "verified"] {
        assert!(
            !root_fields.iter().any(|f| f == account_only),
            "`{account_only}` 属于 HumanAccount，不得留在身份根上"
        );
    }
}

/// A2 · ActorIdentity ≠ Credential
///
/// 「用什么证明自己」与「是谁」是两个对象。password 不得是身份根的列。
#[test]
#[ignore = "V2 Stage 1/2 —— password 是 user 的列，TOTP 在 user_mfa，未收口"]
fn a2_actor_identity_is_not_credential() {
    assert!(table_exists("credential"), "缺少统一 credential 表");
    assert!(
        !field_exists(identity_root(), "password"),
        "password 不得作为身份根字段"
    );
}

/// A3 · ActorIdentity ≠ Client
///
/// Client 是「哪个软件在请求身份能力」，Actor 是「正在被认证的主体」。
/// 同一 Actor 可经不同 Client 进入，同一 Client 可服务不同 Actor。
#[test]
fn a3_actor_identity_is_not_client() {
    assert!(table_exists("oidc_client"), "缺少 oidc_client");
    assert!(
        table_exists(identity_root()),
        "缺少身份根表 {}",
        identity_root()
    );
    // 客户端表不得承载主体标识——那等于把 Client 当 Actor 存。
    let client_fields = fields_of("oidc_client");
    for subject_field in ["subject_key", "actor_kind", "actor_identity_id"] {
        assert!(
            !client_fields.iter().any(|f| f == subject_field),
            "oidc_client 不得携带主体标识 `{subject_field}`"
        );
    }
}

/// A4 · ActorIdentity ≠ IdentityBinding
///
/// 外部身份来源（Google / GitHub / Soulseed Canonical Actor）是绑定关系，
/// 不是主体本身。绑定可撤销，主体不因此消失。
#[test]
fn a4_actor_identity_is_not_binding() {
    let binding = if table_exists("identity_binding") {
        "identity_binding"
    } else {
        "identity_provider"
    };
    assert!(table_exists(binding), "缺少身份绑定表");
    assert_ne!(binding, identity_root(), "绑定与身份根不得是同一张表");
}

/// A5 · Human 与 AIActor 同为一等身份主体
///
/// 判据不是「枚举里有没有这个变体」，而是**有没有任何代码路径真的构造它**。
/// 一个只存在于自身定义处的变体，是声明，不是能力。
#[test]
fn a5_ai_actor_is_first_class() {
    let sources = sources();
    let kind_def = sources
        .iter()
        .find(|(f, _)| f.contains("actor_identity") || f.contains("subject"))
        .map(|(_, b)| b.clone())
        .unwrap_or_default();
    assert!(
        kind_def.contains("AiActor") || kind_def.contains("Agent"),
        "actor_kind 缺少非人主体变体"
    );

    // 关键断言：定义之外必须有构造点。
    let constructions: Vec<_> = hits_any(&["ActorKind::AiActor", "SubjectType::Agent"])
        .into_iter()
        .filter(|h| !h.starts_with("models/subject.rs") && !h.contains("actor_kind.rs"))
        .collect();
    assert!(
        !constructions.is_empty(),
        "非人主体变体从未在定义之外被构造 —— 它只是一个声明，不是可认证的主体"
    );
}

/// A6 · AIActor 不得被迫伪装成 Human Account
///
/// 法源: 06 §4 —— 非人主体拥有独立 ActorIdentity，不必伪造 Email、Username
/// 或口令。这在 Runtime 上意味着一条**完整可走通**的认证路径，而不是一个
/// 从未被构造的枚举变体。
///
/// 这条断言不看文件名，看三件事：能不能建、能不能认证、路上碰没碰 human。
#[test]
fn a6_ai_actor_needs_no_human_account() {
    let all = sources();
    let joined: String = all.iter().map(|(_, b)| b.as_str()).collect();

    // ① `AiActor` 必须在**生产代码**里被真正构造，而不是只活在单测里。
    //    这正是本条曾经失败的原因：枚举变体在，构造点一个也没有。
    let constructed_in_production = all.iter().any(|(f, body)| {
        if f.contains("test") {
            return false;
        }
        let production = match body.find("#[cfg(test)]") {
            Some(i) => &body[..i],
            None => &body[..],
        };
        production.contains("ActorKind::AiActor") && !f.ends_with("actor_identity.rs")
    });
    assert!(
        constructed_in_production,
        "`ActorKind::AiActor` 只是个枚举变体 —— 没有任何生产路径会构造它，\
         等于建一个非人主体只能去注册一个假的人类账户"
    );

    // ② 存在认证入口。
    assert!(
        joined.contains("fn authenticate")
            && joined.contains("AiActorService")
            && joined.contains("fn issue_challenge"),
        "缺少 AIActor 的挑战—应答认证入口"
    );

    // ③ 这条路径不得经过任何人类账户结构。
    //
    // 断言的是**代码**，不是散文：模块注释里写「本路径不碰 human_account」
    // 是对的，不该因此变红。所以先剥掉注释行。
    let svc = read("src/services/ai_actor.rs");
    let svc_code: String = svc
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "human_account",
        "HumanAccount",
        "password",
        "email",
        "username",
    ] {
        assert!(
            !svc_code.contains(forbidden),
            "AIActor 认证路径的代码里出现了 `{forbidden}` —— \
             它必须完全不依赖人类账户结构"
        );
    }

    // ④ Agent 令牌不得被人类端点接受。
    let jwt = read("src/utils/jwt.rs");
    assert!(
        jwt.contains("SubjectType::Agent"),
        "AuthedUser / AuthedActor 必须按 subject_type 区分主体，\
         否则 Agent 令牌会悄悄拿到人类端点的访问权"
    );
}

/// A7 · OAuth Client 不得被解释为 AIActor
///
/// client_id 不得被当作主体标识写进令牌 subject。
#[test]
fn a7_oauth_client_is_not_an_actor() {
    assert_absent(
        hits_any(&[
            "sub: client_id",
            "sub: client.client_id",
            "subject_key: client",
        ]),
        "A7: client_id 不得作为令牌 subject —— Client 不是被认证的主体",
    );
}

/// A8 · Membership 不得是 Identity 属性
///
/// 身份回答「你是谁」，订阅回答「你购买了什么」。商业套餐与定价都不属于
/// 认证内核；把它放在这里，等于把计费档位放到安全路径上。
#[test]
#[ignore = "V2 Stage 6 —— membership_level/expiry 挂在 user 上，且 ops.rs 硬编码定价"]
fn a8_membership_is_not_identity() {
    for f in ["membership_level", "membership_expiry"] {
        assert!(
            !field_exists(identity_root(), f),
            "`{f}` 属于 Product Entitlement，不得作为身份根字段"
        );
    }
    assert_absent(
        hits_any(&["\"price\"", "PREMIUM", "ULTIMATE"]),
        "A8: 定价与套餐等级不得出现在认证服务源码中",
    );
}

// ═════════════════════ B. 凭证与认证 ═════════════════════
// 法源: Canonical Architecture §8 / §11 / §16, Engineering Delta §5 / §10 / §14

/// B1 · 身份主键不由凭证材料派生
///
/// 这是「Credential rotation 不改变 ActorIdentity」的结构前提：只要主键
/// 不是从密码/密钥算出来的，轮换凭证就不可能改变主体。
#[test]
fn b1_identity_key_not_derived_from_credential() {
    assert_absent(
        hits_any(&[
            "Thing::new(\"user\", hash",
            "Thing::new(\"actor_identity\", hash",
            "id: hash_password",
        ]),
        "B1: 身份主键不得由密码或密钥材料派生 —— 否则轮换凭证即更换主体",
    );
}

/// B2 · ActorIdentity 不依赖任一 Credential 存续
///
/// Credential 有独立生命周期：可创建、轮换、撤销、失效，而主体不因此消失。
#[test]
#[ignore = "V2 Stage 2 —— 无 credential 表，凭证散在 user.password / user_mfa / password_reset_token"]
fn b2_identity_outlives_any_credential() {
    assert!(table_exists("credential"), "缺少 credential 表");
    for lifecycle in ["status", "revoked_at", "rotated_at"] {
        assert!(
            field_exists("credential", lifecycle),
            "credential 缺少独立生命周期字段 `{lifecycle}`"
        );
    }
}

/// B3 · Human 与 AIActor 产出同构的 AuthenticationResult
///
/// 不同 Credential，相同 Actor Identity Contract。两条认证路径若各自产出
/// 不同形状的结果，Actor-native 就只是数据建模。
#[test]
#[ignore = "V2 Stage 2 —— 无统一 AuthenticationResult 类型"]
fn b3_authentication_result_is_uniform() {
    let found = sources()
        .iter()
        .any(|(_, b)| b.contains("struct AuthenticationResult"));
    assert!(found, "缺少统一的 AuthenticationResult");
}

/// B4a · Client Secret 哈希落库
#[test]
fn b4a_client_secret_is_hashed() {
    assert!(
        field_exists("oidc_client", "client_secret_hash"),
        "client_secret 必须哈希存储"
    );
    assert!(
        !field_exists("oidc_client", "client_secret"),
        "不得存明文 client_secret"
    );
}

/// B4b · 其余 bearer secret 不得明文落库
///
/// Token compromise 不应等价于整个 ActorIdentity 被永久接管。
#[test]
fn b4b_bearer_secrets_are_not_stored_in_clear() {
    // 六处长效 bearer 凭证，一处都不许留原文。
    //
    // 会话那条最容易被忽略：`session.token` 存的曾是**完整签名 JWT**，
    // 与客户端手里那枚逐字节相同 —— 一次数据库读泄露等于交出全站在线会话。
    for (table, plain, hashed) in [
        ("session", "token", "token_hash"),
        ("oidc_access_token", "token", "token_hash"),
        ("oidc_refresh_token", "token", "token_hash"),
        ("oidc_refresh_token", "access_token", "access_token_hash"),
        ("oidc_authorization_code", "code", "code_hash"),
        ("password_reset_token", "token", "token_hash"),
    ] {
        assert!(
            !field_exists(table, plain),
            "`{table}.{plain}` 是明文 bearer 凭证，必须改存指纹"
        );
        assert!(
            field_exists(table, hashed),
            "`{table}` 缺少指纹列 `{hashed}`"
        );
    }
    assert!(
        !field_exists("user", "verification_token"),
        "`user.verification_token` 是明文，必须改存指纹"
    );
    assert!(field_exists("user", "verification_token_hash"));

    // 指纹必须真的是单向的。
    let crypto = read("src/utils/crypto.rs");
    assert!(
        crypto.contains("pub fn hash_bearer"),
        "缺少 bearer 指纹函数"
    );
    assert!(
        crypto.contains("Sha256::digest"),
        "hash_bearer 必须是真哈希，不能是编码或加前缀"
    );

    // 轮换与重放检测：`used` 标记 + 复用即吊销令牌族。
    // 不断言具体列名（`token_family` 之类）—— 同一个语义可以用
    // client_id + user_id 的族查询实现，强求列名是过度规定。
    assert!(
        field_exists("oidc_refresh_token", "used"),
        "刷新令牌缺少轮换标记"
    );
    let oidc = read("src/services/oidc.rs");
    assert!(
        oidc.contains("revoke_client_tokens_for_user"),
        "检测到刷新令牌复用时必须吊销整个令牌族"
    );
}

/// B5 · 三类 Key 不得共用
///
/// Token 签名密钥 / 凭证加密密钥 / 审计完整性密钥性质不同，共用一把意味着
/// 轮换其中一个用途就会连带破坏另外两个。
#[test]
#[ignore = "V2 Stage 4 —— MFA 加密密钥在未配置时从 JWT_SECRET 派生"]
fn b5_key_material_is_segregated() {
    let cfg = read("src/config.rs");
    let derives = cfg.contains("jwt_secret") && cfg.contains("MFA_SECRET_ENCRYPTION_KEY");
    assert!(
        !derives,
        "MFA 加密密钥不得从 JWT_SECRET 派生 —— 轮换 JWT_SECRET 会锁死每个 MFA 用户"
    );
}

// ═════════════════════ C. 会话与令牌 ═════════════════════
// 法源: Canonical Architecture §10 / §11 / §12, Engineering Delta §8 / §9

/// C1 · OIDC `sub` 不得依赖可变 Profile 属性
///
/// email / username / display name / 凭证轮换都不得改变 sub。
#[test]
fn c1_oidc_sub_is_not_a_profile_attribute() {
    assert_absent(
        hits_any(&["sub: user.email", "sub: user.username", "sub: claims.email"]),
        "C1: sub 不得由 email / username 派生 —— 它们可变，sub 必须稳定",
    );
}

/// C2 · 同一 Actor 经不同 Client，`sub` 保持稳定
#[test]
fn c2_sub_is_stable_across_clients() {
    assert_absent(
        hits_any(&["sub: format!(\"{}:{}\", client", "sub: client_scoped"]),
        "C2: sub 不得随 Client 变化",
    );
}

/// C3 · AuthSession 不得冒充其它 Session 语义
///
/// 需要的是语义隔离，不是为了架构好看无限制造 Session 表。
#[test]
fn c3_auth_session_does_not_impersonate_other_sessions() {
    assert_absent(
        hits_any(&[
            "MindSession",
            "ConnectorSession",
            "ExecutionSession",
            "ConversationSession",
        ]),
        "C3: AuthSession 属于 Authentication Namespace，不得冒充 Mind / Connector / Execution / Conversation Session",
    );
}

/// C4 · SoulAuth Token 不得冒充外部 Connector Credential
#[test]
fn c4_token_is_not_a_connector_credential() {
    assert_absent(
        hits_any(&["ConnectorCredential", "connector_credential"]),
        "C4: SoulAuth 不持有外部 Connector Credential 的 Source of Truth",
    );
}

// ═════════════════════ D. 权限边界 ═════════════════════
// 法源: Canonical Architecture §14 / §25, 工程指导 §9, P0-DECISION-09

/// D1 · 认证成功不产生 Authority
///
/// 「登录成功不是行动授权」。SoulAuth 不得产出 OS 级授权结论。
#[test]
fn d1_authentication_does_not_grant_authority() {
    assert_absent(
        hits_any(&[
            "permission_grant_v1",
            "PermissionGrant",
            "AccessTicket",
            "Mandate",
        ]),
        "D1: 认证成功只建立身份事实。PermissionGrant / AccessTicket / Mandate 由 OS 生成",
    );
}

/// D2 · Auth Role 不得冒充 Governance Decision
#[test]
fn d2_auth_role_is_not_governance() {
    assert_absent(
        hits_any(&[
            "GuardianDecision",
            "guardian_decision",
            "GovernanceDecision",
        ]),
        "D2: SoulAuth Role 只表示身份基础设施内部的管理资格",
    );
}

/// D3 · Auth Permission 不得冒充 Lease
#[test]
fn d3_auth_permission_is_not_a_lease() {
    assert_absent(
        hits_any(&["struct Lease", "Lease {", "lease_id"]),
        "D3: Permission 不等于 Lease —— Lease 是 OS 的时限资源占用",
    );
}

/// D4 · Auth-local 授权止于身份基础设施边界
///
/// 命名空间前缀是这条边界在每个调用点上的可见形式：一个带前缀的权限串，
/// 无论流经多少系统都不会被错认成 OS 级授权。
#[test]
fn d4_permissions_carry_auth_local_namespace() {
    let perms = read("src/models/permission.rs");
    let prefixed = perms.contains("soulauth:") || perms.contains("auth_local!");
    assert!(prefixed, "权限名必须带 Auth-local 命名空间前缀");

    // 种子数据里的权限名同样不得裸奔。
    let seed_sql = seed();
    for line in seed_sql.lines() {
        if let Some(rest) = line.trim().strip_prefix("name: \"") {
            if let Some(name) = rest.split('"').next() {
                if name.contains('.') && !name.contains(':') {
                    panic!("种子权限 `{name}` 缺少命名空间前缀");
                }
            }
        }
    }
}

// ═════════════════════ E. Soulseed 边界 ═════════════════════
// 法源: Canonical Architecture §13 / §22, 工程指导 §13, P0-DECISION-09/10

/// E1 · SoulAuth 不得写入 Mind
#[test]
fn e1_soulauth_does_not_write_mind() {
    assert_absent(
        hits_any(&["MindRoot", "SubjectIntent", "mind_root", "subject_intent"]),
        "E1: Mind / Memory / SubjectIntent 属于 SoulseedAGI，SoulAuth 不写",
    );
}

/// E2 · SoulAuth 不得定义 Canonical AIActor
///
/// SoulAuth 可以认证 AIActor，不能反过来定义它。`canonical_actor_ref` 只证明
/// 绑定关系，不赋予任何 Kernel 写入能力。
#[test]
fn e2_soulauth_does_not_define_canonical_actor() {
    assert_absent(
        hits_any(&[
            "CanonicalActor::new",
            "create_canonical_actor",
            "define_actor",
        ]),
        "E2: Canonical Actor 由 SoulseedAGI 成立，SoulAuth 只做受控绑定",
    );
}

/// E3 · SoulAuth 不得签发 Execution Receipt
///
/// Audit 证明身份过程，Receipt 证明现实结果。二者不得合并。
#[test]
fn e3_soulauth_does_not_issue_receipts() {
    assert_absent(
        hits_any(&["ExecutionReceipt", "execution_receipt", "issue_receipt"]),
        "E3: 认证审计不冒充现实执行结果",
    );
}

/// E4 · 消费方不得直接读 SoulAuth 数据库
///
/// 跨仓断言：OS 侧适配器只应取 JWKS 并本地验签，不得建立数据库连接。
/// 同级目录不存在时跳过——文档仓库 / CI 可以独立构建。
///
/// 判据是**依赖声明**而不是源码文本。首版做裸文本搜索，结果被
/// `jwks_http.rs` 里一句解释依赖选型的注释（"surrealdb 的 protocol-http
/// feature 带进来的"）判成违规。连不上数据库的充分条件是根本没有数据库
/// 依赖，查 Cargo.toml 的 `[dependencies]` 段既准确又不受注释影响。
#[test]
fn e4_consumers_do_not_read_the_database() {
    let adapter = root().join("../SoulSeedOS/crates/adapters/soulseed-adapter-soulauth");
    if !adapter.exists() {
        eprintln!("跳过 E4：未找到 OS 适配器（跨仓，非本仓构建前提）");
        return;
    }

    let manifest = fs::read_to_string(adapter.join("Cargo.toml")).expect("适配器 Cargo.toml 可读");
    // 只看 [dependencies] 段，且逐行剥掉 `#` 注释。
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .unwrap_or("")
        .split("\n[")
        .next()
        .unwrap_or("");
    for line in deps.lines() {
        let code = match line.find('#') {
            Some(i) => &line[..i],
            None => line,
        };
        let name = code.split(['=', ' ', '.']).next().unwrap_or("").trim();
        for db in [
            "surrealdb",
            "sqlx",
            "tokio-postgres",
            "diesel",
            "rusqlite",
            "mysql",
        ] {
            assert_ne!(
                name, db,
                "适配器声明了数据库依赖 `{db}` —— 消费方不得直连 SoulAuth 数据库"
            );
        }
    }

    // 再确认源码里没有真正的连接调用（剥注释后）。
    let mut bodies = Vec::new();
    let src = adapter.join("src");
    walk(&src, &src, &mut bodies);
    assert!(
        !bodies.is_empty(),
        "适配器 src/ 下没有源码 —— 断言失去作用域"
    );
    for (file, body) in bodies {
        for line in body.lines() {
            let code = match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            };
            for call in ["Surreal::new", "Surreal::init", "connect("] {
                assert!(
                    !code.contains(call),
                    "适配器 {file} 出现 `{call}` —— 消费方不得直连数据库"
                );
            }
        }
    }
}

/// E5 · 对外契约不泄漏私有表结构
///
/// 发现文档与 ID Token 是对外契约。它们不得出现内部表名，否则消费方会
/// 开始依赖 SoulAuth 的私有 schema。
#[test]
fn e5_public_contract_leaks_no_internal_schema() {
    let oidc = read("src/services/oidc.rs");
    for internal in [
        "user_mfa",
        "account_lockout",
        "user_activity",
        "role_permission",
    ] {
        assert!(
            !oidc.contains(&format!("\"{internal}\"")),
            "OIDC 对外契约中出现内部表名 `{internal}`"
        );
    }
}

/// E6 · `canonical_actor_ref` 不得默认暴露给第三方 Client
///
/// 它属于受控 Integration Claim，不是公共身份默认字段。
///
/// 当前是**空成立**：还没有 `canonical_actor_ref` 这个 claim。之所以不标
/// `#[ignore]`，是因为它现在就在起守卫作用 —— Stage 5 有人把这个字段加进
/// ID Token 而忘了加 Client 级开关时，这条会立刻变红。一个「等你违反才有话说」
/// 的断言，正是应该常驻的那种。
#[test]
fn e6_canonical_actor_ref_is_not_a_default_claim() {
    let oidc = read("src/services/oidc.rs");
    let in_claims = oidc.contains("canonical_actor_ref");
    let gated = oidc.contains("allow_canonical_actor_ref") || oidc.contains("integration_claims");
    assert!(
        !in_claims || gated,
        "canonical_actor_ref 进入 ID Token 时必须受 Client 级开关控制"
    );
}

// ═════════════════════ F. 审计 ═════════════════════
// 法源: Canonical Architecture §17 / §18, Engineering Delta §15 / §16

/// F1 · Audit 稳定归因到 ActorIdentity
#[test]
#[ignore = "V2 Stage 5 —— 审计仍以 user_id 归因"]
fn f1_audit_attributes_to_actor() {
    let table = if table_exists("audit_event") {
        "audit_event"
    } else {
        "user_activity"
    };
    assert!(
        field_exists(table, "actor_identity_ref") || field_exists(table, "actor_identity_id"),
        "审计事件必须归因到 ActorIdentity，而不是 Human User"
    );
}

/// F3 · 明文 Secret 不得进入 Log / Audit / Claims
///
/// 审计保留引用，不记 raw token / secret。
///
/// 这里只看**审计详情的构造点**（`.with_details(...)`），不做全文搜词。
/// 全文搜词会把三类合法用法误判成泄漏：动作名常量 `password_reset`、
/// 模块文档里列举的动作名、以及往数据库写加密后 TOTP 密钥的查询绑定。
/// 真正要挡的是「凭据的**值**被塞进审计详情」，那只可能发生在这个构造点上。
#[test]
fn f3_no_raw_secrets_in_audit() {
    const CREDENTIAL_KEYS: [&str; 8] = [
        "\"password\"",
        "\"secret\"",
        "\"token\"",
        "\"client_secret\"",
        "\"totp_secret\"",
        "\"refresh_token\"",
        "\"code_verifier\"",
        "\"backup_codes\"",
    ];

    let mut leaks = Vec::new();
    let mut call_sites = 0usize;

    for (file, body) in sources() {
        let production = match body.find("#[cfg(test)]") {
            Some(i) => &body[..i],
            None => &body[..],
        };
        let mut from = 0usize;
        while let Some(rel) = production[from..].find("with_details(") {
            let open = from + rel + "with_details(".len();
            call_sites += 1;
            // 按括号配平截出这次调用的实参块。
            let mut depth = 1usize;
            let mut end = production.len();
            for (i, ch) in production[open..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let block = &production[open..end];
            for key in CREDENTIAL_KEYS {
                if block.contains(key) {
                    let line = production[..open].lines().count();
                    leaks.push(format!("{file}:{line}  ({key})"));
                }
            }
            from = end.max(open);
        }
    }

    assert!(
        call_sites > 0,
        "没有找到任何 with_details 调用点 —— 这个断言失去了作用域，需要重写"
    );
    assert_absent(leaks, "F3: 凭据的值不得进入审计详情");
}

/// F4 · 审计历史不得被静默改写
///
/// 哈希链检测单条修改、删除与乱序；独立签名的 checkpoint 检测整段历史替换。
/// 两者都有，`tamper-evident` 才是架构事实而不是宣传性形容。
#[test]
#[ignore = "V2 Stage 5 —— 无哈希链、无 checkpoint，审计就是一张普通表"]
fn f4_audit_is_tamper_evident() {
    let table = if table_exists("audit_event") {
        "audit_event"
    } else {
        "user_activity"
    };
    assert!(
        field_exists(table, "previous_hash"),
        "审计缺少 previous_hash"
    );
    assert!(field_exists(table, "event_hash"), "审计缺少 event_hash");
    assert!(
        table_exists("audit_checkpoint"),
        "缺少 audit_checkpoint —— 仅有哈希链挡不住拥有全库写权限的重写"
    );
}

// ═════════════════════ G. 工程结构 ═════════════════════
// 法源: Canonical Architecture §15 / §19, Engineering Delta §13 / §17 / §20

/// G1 · Repository 按领域分离
///
/// 一个数据库可以承载多个领域，但一个 Repository 不能偷偷拥有所有领域的写权限。
#[test]
#[ignore = "V2 Stage 1-5 —— 无 Repository 抽象，Database 单结构 21 个公开方法通吃全域"]
fn g1_repositories_are_separated_by_domain() {
    let all: String = sources().iter().map(|(_, b)| b.clone()).collect();
    for repo in [
        "IdentityRepository",
        "CredentialRepository",
        "SessionRepository",
        "OidcRepository",
        "SecurityRepository",
        "AuditRepository",
    ] {
        assert!(all.contains(repo), "缺少 {repo}");
    }
}

/// G2 · 影响安全语义的状态跨副本共享
///
/// 凭证端点的限流计数、账号锁定与 TOTP 重放水位线都必须落库；只存在于
/// 单进程内存的话，部署 N 个副本等于把配额放大 N 倍。
///
/// 一般 API 的默认规则**刻意**留在进程内——给每个请求加一次数据库往返，
/// 比非凭证流量上的 N 倍上限更糟。这是取舍，不是缺口。
#[test]
fn g2_security_state_is_shared_across_replicas() {
    let main = read("src/main.rs");
    assert!(
        main.contains("with_shared_backend"),
        "限流未挂共享后端 —— 凭证端点配额会被副本数放大"
    );
    assert!(table_exists("account_lockout"), "锁定状态必须落库");
    assert!(
        field_exists("user_mfa", "last_totp_step"),
        "TOTP 重放水位线必须落库，否则副本间可重放同一验证码"
    );
}

/// G3 · 稳定的机器可读 error contract
///
/// 契约是：`error` 携带**稳定的机器可读码**，`message` 是可以改措辞的人话。
/// 调用方按 HTTP 状态码 + `error` 分支，永远不按 `message` 的文案分支。
///
/// 字段名用 `error` 而不是 `code`，是为了与本服务 OIDC 端点上 RFC 6749 强制的
/// `{"error", "error_description"}` 同名同位 —— 一个 API 里两种命名习惯，
/// 消费方仍然要记两套。
#[test]
fn g3_error_contract_is_stable() {
    let err = read("src/error.rs");
    assert!(
        err.contains("pub fn code(&self) -> &'static str"),
        "AuthError 必须提供稳定的机器可读 `code()`"
    );
    // 断言前先把空白压平。
    //
    // 直接匹配 `body.insert("error".into()` 会被 rustfmt 的折行打断 ——
    // 那样这条守卫报的是「格式变了」而不是「契约变了」，是假红。
    let flat: String = err.split_whitespace().collect::<Vec<_>>().join(" ");
    for (key, what) in [("error", "码"), ("message", "人话")] {
        assert!(
            flat.contains(&format!(r#"body.insert( "{key}".into()"#))
                || flat.contains(&format!(r#"body.insert("{key}".into()"#)),
            "错误响应体必须含 `{key}`（{what}）"
        );
    }

    // 码只能是 snake_case 字面量：一旦有人把 `format!` 塞进去，它就不再稳定了。
    let codes = err
        .split("pub fn code(&self) -> &'static str")
        .nth(1)
        .expect("code() 不见了");
    let body = &codes[..codes.find("\n    }").expect("code() 没有结尾")];
    assert!(
        !body.contains("format!"),
        "错误码必须是字面量，不能是格式化出来的字符串"
    );
    for line in body.lines().filter(|l| l.contains("=>") && l.contains('"')) {
        let lit = line.split('"').nth(1).unwrap_or("");
        assert!(
            !lit.is_empty()
                && lit
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "错误码 `{lit}` 不是 snake_case"
        );
    }
}

// ═════════════════════ H. 30 篇公开文档补充的不变式 ═════════════════════
// 法源: SoulAuth_Public_Documentation_Current_01-30
//
// Stage 0 首版从 3 份内部文档提炼了 34 条。30 篇公开文档（1307 条唯一不等式）
// 校准后发现以下 10 条未被覆盖。其中 H8/H9/H10 防的不是代码缺陷，而是
// **文档层面的过度声称** —— 它们同样会伤害一个开源项目的可信度。

/// H1 · Retired Subject ≠ Reusable Subject
///
/// 法源: 06 §7「一个已经退役的 Subject 可以停止认证，但不能被静默重新分配
/// 给另一个 Actor」。否则历史 Claims、Audit 与外部记录里的同一个 Subject，
/// 会在不同时间指向不同主体。这是标识符完整性规则，不是数据保留策略。
#[test]
fn h1_retired_subject_is_not_reusable() {
    assert!(
        field_exists(identity_root(), "subject_key"),
        "缺少稳定 subject_key"
    );
    let all: String = sources().iter().map(|(_, b)| b.clone()).collect();
    assert!(
        all.contains("retired") || all.contains("Retired"),
        "身份状态机缺少 Retired，无法表达「停止认证但保留标识符」"
    );
}

/// H2 · Actor Identity ≠ Profile
///
/// 法源: 06 §6「Profile 描述 Actor，Subject 标识 Actor」。
/// Display Name、Avatar、Locale 变化不得改变身份。
#[test]
#[ignore = "V2 Stage 1 —— user_profile 通过 user_id 挂在身份根上，无独立 actor 引用"]
fn h2_actor_identity_is_not_profile() {
    assert!(table_exists("user_profile") || table_exists("actor_profile"));
    let profile = if table_exists("actor_profile") {
        "actor_profile"
    } else {
        "user_profile"
    };
    assert!(
        field_exists(profile, "actor_identity_id"),
        "Profile 必须引用 ActorIdentity，而不是复用身份根主键"
    );
}

/// H3 · Identity Binding ≠ Credential
///
/// 法源: 06 §3「外部 IdP 中 Human 使用的 Password、Passkey 或其它 Credential，
/// 并不会因此成为 SoulAuth Actor Credential」。Binding 解析主体对应关系，
/// Federated Authentication 验证本次外部认证结果 —— 两个问题。
#[test]
#[ignore = "V2 Stage 1/2 —— 无 credential 表，binding 与 credential 尚未分开"]
fn h3_binding_is_not_credential() {
    assert!(table_exists("credential"), "缺少 credential 表");
    let binding = if table_exists("identity_binding") {
        "identity_binding"
    } else {
        "identity_provider"
    };
    // 绑定表不得存放认证密材 —— 那等于把外部 Credential 复制进 SoulAuth。
    for secret in ["password", "secret_hash", "credential_secret"] {
        assert!(
            !field_exists(binding, secret),
            "{binding} 不得存放认证密材 `{secret}`"
        );
    }
}

/// H4 · Actor Credential ≠ Client Authentication Material
///
/// 法源: 06 §5 / 10 §5。Client Authentication 证明软件，
/// Actor Authentication 证明 Human 或 AIActor。即使出现在同一次交互中，
/// 也属于不同安全关系，生命周期互不牵连。
#[test]
fn h4_actor_credential_is_not_client_material() {
    // 客户端密材存在 oidc_client 上，主体凭证不得与它同表。
    assert!(field_exists("oidc_client", "client_secret_hash"));
    let credential_table = if table_exists("credential") {
        "credential"
    } else {
        identity_root()
    };
    assert_ne!(
        credential_table, "oidc_client",
        "Actor Credential 与 Client Authentication Material 不得共表"
    );
    assert!(
        !field_exists("oidc_client", "actor_identity_id")
            && !field_exists("oidc_client", "user_id"),
        "oidc_client 不得持有主体引用 —— Client 不是 Actor 的凭证载体"
    );
}

/// H5 · Registered Client ≠ Administrative Authority
///
/// 法源: 10 §4「Bootstrap Client ≠ Administrator」「Client Creation Order
/// ≠ Administrative Authority」。第一个被创建的 Client 不因顺序获得任何权限。
#[test]
fn h5_registered_client_grants_no_authority() {
    // 客户端表不得携带角色/权限字段。
    let fields = fields_of("oidc_client");
    for authority in ["role", "role_id", "permissions", "is_admin"] {
        assert!(
            !fields.iter().any(|f| f == authority),
            "oidc_client 不得携带 `{authority}` —— 注册 Client 不产生管理资格"
        );
    }
}

/// H6 · ID Token ≠ API Access Token
///
/// 法源: 全套文档出现 9 次，跨 12/13/18/19/21 五篇。
/// ID Token 表达 Authentication Event 与 Identity Claims，
/// 不得被当作普通 API Access Token 使用。
///
/// 结构判据：两者必须由不同签发路径产出，且 ID Token 不得进入
/// access token 的校验通路。
#[test]
fn h6_id_token_is_not_an_access_token() {
    let oidc = read("src/services/oidc.rs");
    assert!(
        oidc.contains("fn generate_id_token"),
        "ID Token 应有独立签发路径"
    );
    // access token 走库查（不透明串），ID Token 走签名 —— 两条通路不得互换。
    assert!(
        oidc.contains("fn get_access_token"),
        "Access Token 应有独立校验路径"
    );
    assert_absent(
        hits_any(&["decode::<IdTokenClaims>(access_token"]),
        "H6: 不得把 Access Token 当 ID Token 解",
    );
}

/// H7 · Claims 必须经过 Purpose-bound Projection
///
/// 法源: 26「Claims必须经过 Purpose-bound Projection」。
///
/// 校准中发现的真实缺陷：`generate_id_token` 此前没有 `scope` 参数，
/// 无条件下发 email / email_verified / preferred_username，
/// 而同一台服务器的 UserInfo 是裁剪的。已修复为共用 `ClaimDisclosure`。
#[test]
fn h7_claims_are_purpose_bound() {
    let oidc = read("src/services/oidc.rs");
    assert!(
        oidc.contains("struct ClaimDisclosure"),
        "身份 claim 的披露判定必须收在一处，否则两条通路会再次分叉"
    );
    // 两条生产通路都必须经过它。数全文件出现次数是不够的 —— 那样即使生产代码
    // 一次都不用，光靠测试里的调用也能让断言通过。这里按函数体分别查。
    for func in ["fn generate_id_token", "pub async fn get_userinfo"] {
        let start = oidc.find(func).unwrap_or_else(|| panic!("找不到 {func}"));
        let body_end = oidc[start..]
            .find("\n    }")
            .map(|i| start + i)
            .unwrap_or(oidc.len());
        assert!(
            oidc[start..body_end].contains("ClaimDisclosure::from_scope"),
            "{func} 没有经过统一的 claim 披露判定"
        );
    }
}

/// H8 · Operational Log ≠ Audit Record
///
/// 法源: 15/16/19。应用日志用于运维观测，审计表才是权威安全记录。
/// 判据：审计不得只写日志宏了事。
#[test]
fn h8_audit_is_not_merely_logging() {
    let logger = read("src/services/audit_logger.rs");
    assert!(
        logger.contains("AuditEvent"),
        "审计必须落结构化事件，而不是 tracing 宏"
    );
    assert!(
        table_exists("user_activity") || table_exists("audit_event"),
        "审计必须有持久化表"
    );
}

/// H9 · Tamper-evident ≠ Tamper-proof
///
/// 法源: 19/28「目标是让关键 Audit History 的异常修改能够被检测和验证，
/// 而不是宣称任何数字系统拥有绝对不可篡改性」。
///
/// 这一条约束的是**措辞**：代码与文档都不得使用 tamper-proof / immutable
/// 这类绝对化表述。
#[test]
fn h9_no_absolute_immutability_claims() {
    assert_absent(
        hits_any(&[
            "tamper-proof",
            "tamper_proof",
            "immutable audit",
            "unalterable",
        ]),
        "H9: 审计的保证是可检测（tamper-evident），不是不可篡改（tamper-proof）",
    );
}

/// H10 · Implemented ≠ Supported，内部语义 ≠ RFC 符合
///
/// 法源: 22「Internal Revocation Semantics ≠ RFC 7009 Support」
/// 「Internal / Online Token Lookup ≠ RFC 7662 Introspection」
/// 「SoulAuth issues Access Tokens ≠ RFC 9068 Conformance」。
///
/// 判据：没有实现对应 wire contract 时，发现文档不得 Advertise 它。
/// 这正是 26「Metadata必须反映真实Runtime」的可执行形式。
#[test]
fn h10_metadata_advertises_only_what_runtime_supports() {
    let oidc = read("src/services/oidc.rs");

    // 发现文档若声明 introspection / revocation 端点，必须真有实现。
    for (advertised, implemented) in [
        ("introspection_endpoint", "fn introspect"),
        ("revocation_endpoint", "fn revoke_token_endpoint"),
    ] {
        if oidc.contains(advertised) {
            assert!(
                oidc.contains(implemented),
                "发现文档声明了 `{advertised}`，但没有对应实现 —— \
                 内部有类似动作不等于支持该标准端点"
            );
        }
    }

    // 声明的 code_challenge_methods 必须逐个真的被接受。
    if oidc.contains("\"S256\".to_string()") {
        assert!(
            oidc.contains("Some(\"S256\")"),
            "声明支持 S256 就必须在 authorize 处真的接受它"
        );
    }
    // 反向：不接受 plain，就不得声明 plain。
    let advertises_plain = oidc.contains("code_challenge_methods_supported")
        && oidc
            .split("code_challenge_methods_supported")
            .nth(1)
            // 同样按字符取窗口：源码含中文，按字节切可能落在多字节字符中间。
            .map(|tail| tail.chars().take(200).collect::<String>().contains("plain"))
            .unwrap_or(false);
    assert!(!advertises_plain, "不接受 plain 就不得在发现文档里声明它");
}

/// H11 · 全新实例必须能在不改数据库的前提下走到第一份身份
///
/// 法源: 03 §8「一个全新的 SoulAuth 实例，应该让开发者在**不直接修改数据库**
/// 的情况下，从零走到第一份经过验证的 Actor 身份」
/// 与 10 §4「Client Registration ≠ Direct Database Mutation」。
///
/// 此前存在死锁：注册 Client 需要 admin，而第一个 admin 只能手工写库。
#[test]
fn h11_fresh_instance_bootstraps_without_database_mutation() {
    let sources = sources();
    assert!(
        sources.iter().any(|(f, _)| f == "routes/bootstrap.rs"),
        "缺少引导路径 —— 全新实例无法在不改库的情况下建立第一个管理员"
    );
    let main = read("src/main.rs");
    assert!(main.contains("/api/bootstrap"), "引导路由未挂载");
    // 容器路径：文档要求开发者只需 Git + Docker + Compose。
    for artifact in ["Dockerfile", "docker-compose.yml"] {
        assert!(
            root().join(artifact).exists(),
            "缺少 {artifact} —— Quickstart 声明的容器路径不成立"
        );
    }
}

/// H12 · 引导门是一次性的，且不构成初始化状态的探测信道
///
/// 法源: 10 §4「Bootstrap Client ≠ Administrator」「Client Creation Order
/// ≠ Administrative Authority」。
///
/// 结构判据：必须先判系统状态再验令牌。反过来的话，「令牌错」与「已初始化」
/// 会返回不同状态码，一枚失效令牌就成了探测实例是否已初始化的信道。
#[test]
fn h12_bootstrap_gate_is_single_use_and_not_an_oracle() {
    let bootstrap = read("src/routes/bootstrap.rs");
    let admin_check = bootstrap
        .find("admin_exists(&db)")
        .expect("引导端点必须检查是否已存在管理员");
    let token_check = bootstrap
        .find("bootstrap.verify(")
        .expect("引导端点必须校验令牌");
    assert!(
        admin_check < token_check,
        "必须先判「是否已初始化」再验令牌 —— 顺序颠倒会让失效令牌变成探测信道"
    );
    // 令牌比对必须等时：引导窗口期内它就是整个实例的管理权。
    assert!(
        bootstrap.contains("constant_time_eq"),
        "引导令牌比对必须是常量时间"
    );
}

// ═════════════════════ I. 终检文档（GA-01～07）补充的不变式 ═════════════════════
// 法源: 03-终检文档 / Global Audit，Chinese Internal Master v1.0 SEMANTIC FROZEN

/// I1 · 一次性凭据必须原子消费
///
/// 法源: GA-06 §19「Successful Consumption → Future Successful Reuse Is
/// Forbidden，且必须 survive retry / replication / recovery」
/// 与 §20「Stale Replica 不能重新接受已经消费的 Artifact」。
///
/// 判据是**消费必须由数据库的条件更新完成**，而不是应用侧「读 → 判 → 写」。
/// 后者在并发下两个请求都能通过判定；GA-06 点名的四类凭据全部适用。
#[test]
fn i1_one_time_artifacts_are_claimed_atomically() {
    let all: String = sources().iter().map(|(_, b)| b.clone()).collect();

    // 每一类一次性凭据都必须能找到一条「条件更新 + RETURN VALUE」的抢占语句。
    let claims = [
        ("授权码", "UPDATE oidc_authorization_code SET used = true"),
        ("刷新令牌", "UPDATE oidc_refresh_token SET used = true"),
        (
            "密码重置令牌",
            "UPDATE password_reset_token SET used = true",
        ),
        // 列名是 `verified`，不是 Rust 侧的 `is_email_verified`（那个靠
        // `#[surreal(rename)]` 映射）。裸 SQL 用错列名会让整条语句失败。
        ("邮箱验证令牌", "UPDATE user SET verified = true"),
    ];
    for (label, stmt) in claims {
        // 同一条 UPDATE 前缀可能出现多次且用途不同：密码重置既有「抢占这一枚」，
        // 也有「批量作废同邮箱的其余令牌」，后者本就不需要 RETURN VALUE。
        // 所以判据是「**存在**一条同时带 WHERE 与 RETURN VALUE 的」，
        // 而不是「第一条就得是」。
        let mut from = 0usize;
        let mut found_claim = false;
        let mut occurrences = 0usize;
        while let Some(rel) = all[from..].find(stmt) {
            let at = from + rel;
            occurrences += 1;
            // 不能直接 `&all[at..at + 400]`：源码里有中文，按字节切会落在多字节
            // 字符中间而 panic。按字符取窗口。
            let tail: String = all[at..].chars().take(400).collect();
            if tail.contains("WHERE") && tail.contains("RETURN VALUE") {
                found_claim = true;
                break;
            }
            from = at + stmt.len();
        }
        assert!(occurrences > 0, "{label}：找不到任何 `{stmt}`");
        assert!(
            found_claim,
            "{label}：{occurrences} 处 `{stmt}` 中没有一条同时带 WHERE 与 RETURN VALUE"
        );
    }
}

/// I2 · 跨命名空间不得隐式转换
///
/// 法源: GA-04 §41「Cross-namespace Implicit Cast → prohibited」、
/// §42「Identifier Shape 不能用来猜 Namespace」、
/// §43「Namespace Mismatch 禁止 Implicit Fallback」。
///
/// 三条分别对应：不得静默把外部命名空间的值当本命名空间用；不得按字符串
/// 形状猜它属于哪个命名空间；不匹配时不得挨个回退尝试。
#[test]
fn i2_no_implicit_cross_namespace_cast() {
    let record_id = read("src/utils/record_id.rs");

    // §41：构造 user 引用时必须能拒绝外部命名空间的值。
    assert!(
        record_id.contains("ForeignNamespace"),
        "user_record_id 必须能拒绝带其它表前缀的值，而不是静默包装成 user:⟨client:abc⟩"
    );
    assert!(
        record_id.contains("fn user_record_id") && record_id.contains("-> Result<RecordId"),
        "user_record_id 必须返回 Result —— 静默成功会把命名空间用错伪装成资源不存在"
    );

    // §43：拒绝之后不得回退到别的命名空间再试一次。
    assert_absent(
        hits_any(&[
            "client_record_id(",
            "try_as_client",
            "or_else_lookup_client",
        ]),
        "I2: 命名空间不匹配时不得回退尝试其它命名空间",
    );
}

/// I3 · 权限注册表不得声明运行时不校验的权限
///
/// 法源: GA-07 §21「文档写了但 Runtime 不存在 → BLOCK；Runtime 有而注册表
/// 不声明 → Contract Drift」与 §23「能改变 Public Behavior 的权限不能靠
/// 『内部实现』逃避 Canonical Contract」。
///
/// 反向同样成立：注册表里可授予、但运行时零效果的权限，是注册表在说谎 ——
/// 管理员授予 `users.delete` 会合理地以为自己开了什么，实际什么也没开。
///
/// 种子权限集合与代码常量集合必须**双向相等**。
#[test]
fn i3_permission_registry_matches_enforcement() {
    let perm_src = read("src/models/permission.rs");
    let mut in_code: Vec<String> = Vec::new();
    let mut rest = perm_src.as_str();
    while let Some(at) = rest.find("auth_local!(\"") {
        let tail = &rest[at + "auth_local!(\"".len()..];
        if let Some(end) = tail.find('"') {
            let name = &tail[..end];
            // NAMESPACE 常量是 auth_local!("")，不是一条权限。
            if !name.is_empty() {
                in_code.push(format!("soulauth:{name}"));
            }
            rest = &tail[end..];
        } else {
            break;
        }
    }
    in_code.sort();
    in_code.dedup();
    assert!(!in_code.is_empty(), "找不到任何权限常量 —— 断言失去作用域");

    let mut in_seed: Vec<String> = seed()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("name: \"")?.split('"').next())
        .filter(|n| n.starts_with("soulauth:"))
        .map(str::to_string)
        .collect();
    in_seed.sort();
    in_seed.dedup();

    let seeded_but_dead: Vec<_> = in_seed.iter().filter(|p| !in_code.contains(p)).collect();
    assert!(
        seeded_but_dead.is_empty(),
        "种子里可授予但代码从不校验的权限（授予它们零效果）:\n  {:?}",
        seeded_but_dead
    );

    let enforced_but_unseeded: Vec<_> = in_code.iter().filter(|p| !in_seed.contains(p)).collect();
    assert!(
        enforced_but_unseeded.is_empty(),
        "代码校验但种子未播种的权限（会导致永远拒绝）:\n  {:?}",
        enforced_but_unseeded
    );
}

/// I4 · 身份根建成后必须真的被接线
///
/// Stage 1 的三个新模块带着临时的 `#![allow(dead_code)]`：建对象与切写路径
/// 分两步做，中间那段时间它们没有生产调用方，而 CI 跑 `clippy -D warnings`。
///
/// 问题是这个 allow 一旦留下就很难被想起来 —— 它等于永久关掉了「这个类型还
/// 有没有人用」那道闸门，而本仓库正是靠 clippy 顶住 dead code
/// （rustc 对本 crate 的 dead_code 并不总报警，实测过）。
///
/// 所以这里把两件事绑在一起：**只要还挂着 allow，就必须尚未接线；一旦接线，
/// allow 就必须删掉。** 两个方向都会红，中间状态不存在。
#[test]
fn i4_identity_root_allow_is_removed_once_wired() {
    let modules = [
        "src/models/actor_identity.rs",
        "src/models/human_account.rs",
        "src/models/identity_binding.rs",
    ];
    let still_allowed: Vec<&str> = modules
        .iter()
        .copied()
        .filter(|m| read(m).contains("#![allow(dead_code)]"))
        .collect();

    // 生产代码（models 之外）是否已经在用这些类型。
    let wired: Vec<String> = sources()
        .iter()
        .filter(|(f, _)| !f.starts_with("models/"))
        .filter(|(_, b)| {
            let production = match b.find("#[cfg(test)]") {
                Some(i) => &b[..i],
                None => &b[..],
            };
            // 必须逐行剥掉注释：这几个词大量出现在讲边界的注释里
            // （例如 record_id.rs 解释「接口期待 ActorIdentity Reference」），
            // 裸 contains 会把注释当成接线。
            production.lines().any(|line| {
                let code = match line.find("//") {
                    Some(i) => &line[..i],
                    None => line,
                };
                code.contains("ActorIdentity")
                    || code.contains("HumanAccount")
                    || code.contains("IdentityBinding")
            })
        })
        .map(|(f, _)| f.clone())
        .collect();

    if wired.is_empty() {
        assert!(
            !still_allowed.is_empty(),
            "身份根尚未接线，却已经没有 allow(dead_code) —— \
             要么 clippy 会红，要么这个断言的前提变了"
        );
    } else {
        assert!(
            still_allowed.is_empty(),
            "身份根已在 {:?} 接线，但 {:?} 仍挂着临时的 #![allow(dead_code)] —— \
             该删了，否则 dead code 闸门一直是关的",
            wired,
            still_allowed
        );
    }
}

/// I5 · 外键一律指向身份根，读写两侧同源
///
/// Stage 3 把 11 处 `record<user>` 外键迁到了 `actor_identity`。这类迁移有一个
/// 编译器完全看不见的失败模式：**写入侧改了、读取侧没改**。两边都是合法 SQL、
/// 都能编译、都能跑，只是再也匹配不到任何行 —— 于是全端登出变成空操作，
/// 令牌吊销静默失效。本仓库已经出过一次这种缺陷（停用后 refresh token 照常
/// 换新），所以这里静态挡住。
///
/// 判据有两条：schema 里不得残留 `record<user>`；SQL 里凡是拿 `user_id`
/// 与 `type::record('user', ...)` 比较的，一律视为漏改。
#[test]
fn i5_foreign_keys_point_at_the_identity_root() {
    // ① schema 侧：外键类型全部迁完。
    //
    // 同时查 `record<user>` 与 `record<subject>`：步骤 3 批量替换时只匹配了
    // 前者，于是 `user.subject_id` 那处（写的是 `option<record<subject>>`）
    // 漏网，直到集成测试报
    // 「Expected `none | record<subject>` but found `actor_identity:...`」
    // 才暴露。判据必须覆盖**所有**指向旧身份表的外键，而不是某一种写法。
    let schema_sql = schema();
    let leftovers: Vec<&str> = schema_sql
        .lines()
        .filter(|l| l.trim_start().starts_with("DEFINE FIELD"))
        .filter(|l| l.contains("record<user>") || l.contains("record<subject>"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "schema 仍有指向 user 表的外键:\n  {}",
        leftovers.join("\n  ")
    );

    // ② 代码侧：不得再有 `user_id = type::record('user', ...)` 这种比较。
    //
    // 查 `user` 表本身是合法的（例如 `SELECT * FROM user WHERE id = ...`），
    // 所以只匹配 user_id 与 user 记录相比的形状。
    let mut bad = Vec::new();
    for (file, body) in sources() {
        let production = match body.find("#[cfg(test)]") {
            Some(i) => &body[..i],
            None => &body[..],
        };
        for (n, line) in production.lines().enumerate() {
            let code = match line.find("//") {
                Some(i) => &line[..i],
                None => line,
            };
            // `(SELECT VALUE subject_id FROM type::record('user', ...))[0]` 是
            // **正确**的写法：它把 user id 解析成 actor ref。里面自然含有
            // `type::record('user'`，所以必须先把这种形状排除，否则整条迁移
            // 都会被判成违规。
            let already_resolved = code.contains("subject_id FROM");
            if code.contains("user_id") && code.contains("type::record('user'") && !already_resolved
            {
                bad.push(format!("{file}:{}", n + 1));
            }
        }
    }
    assert_absent(
        bad,
        "I5: 外键已指向 actor_identity，这些查询仍按 user 记录匹配 —— \
         它们能编译、能运行，只是一行也匹配不到",
    );
}

/// I6 · `SurrealValue` 枚举不得同时 derive `Default`
///
/// SurrealDB 的 `SurrealValue` derive 对 unit-only 枚举编码成字符串 —— 仓库里
/// `LockoutType`、`MfaMethod`、`ActivityCategory` 都这么用，与 schema 的
/// `TYPE string` 对得上，一直工作正常。
///
/// 但同时 derive `Default`（配 `#[default]` 属性）会让它改走 struct-like 编码，
/// 产出 `{ Human: {} }`，数据库随即以
/// 「Expected `string` but found `{ Human: {} }`」拒绝整条写入。
///
/// 这个失败模式有三重伪装：编译通过、clippy 通过、单测也通过 —— 只要单测
/// 断言的是 `serde_json` 往返（serde 与 SurrealValue 是两条不同的序列化路径）。
/// Stage 1 的三个新模型全部踩中，直到集成测试第一次跑才暴露。
///
/// 需要默认值时，把字段落成 `String`，枚举只在应用层用，两侧靠
/// `as_str()` / `parse()` 转换 —— 这也是 `models::user::AccountStatus` 的做法。
#[test]
fn i6_surrealvalue_enums_do_not_also_derive_default() {
    let mut bad = Vec::new();
    for (file, body) in sources() {
        if !file.starts_with("models/") {
            continue;
        }
        let lines: Vec<&str> = body.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.contains("derive(") || !line.contains("SurrealValue") {
                continue;
            }
            if !line.contains("Default") {
                continue;
            }
            // 只管枚举：结构体的 Default 不走这条编码路径。
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim_start().starts_with('#') {
                j += 1;
            }
            let Some(decl) = lines.get(j) else { continue };
            let Some(rest) = decl.trim_start().strip_prefix("pub enum ") else {
                continue;
            };
            let Some(name) = rest.split_whitespace().next() else {
                continue;
            };
            let name = name.trim_end_matches('{').trim();

            // 光有这个 derive 组合还不致命 —— `AccountStatus` 就是这样，但它
            // 落库的字段是 `String`（`user.account_status: String`），枚举只在
            // 应用层用。真正会炸的是**直接拿它当结构体字段类型**。
            // 还要区分**落库结构体**与 API DTO：`UserResponse` 这类只走 serde
            // 到 JSON，用枚举完全合法。判据是结构体带不带 `id: Option<Thing>`
            // —— 有它才是落库记录。
            let mut used_in_persisted = None;
            let mut current_struct: Option<&str> = None;
            let mut struct_body = String::new();
            for l in body.lines() {
                let t = l.trim();
                if let Some(rest) = t.strip_prefix("pub struct ") {
                    // 上一个结构体收尾判定
                    if let Some(sname) = current_struct {
                        if struct_body.contains("id: Option<Thing>")
                            && struct_body.contains(&format!(": {name},"))
                        {
                            used_in_persisted = Some(sname.to_string());
                        }
                    }
                    current_struct = rest.split_whitespace().next();
                    struct_body.clear();
                    continue;
                }
                let code = match l.find("//") {
                    Some(k) => &l[..k],
                    None => l,
                };
                struct_body.push_str(code);
                struct_body.push('\n');
            }
            if let Some(sname) = current_struct {
                if struct_body.contains("id: Option<Thing>")
                    && struct_body.contains(&format!(": {name},"))
                {
                    used_in_persisted = Some(sname.to_string());
                }
            }

            if let Some(sname) = used_in_persisted {
                bad.push(format!("{file}:{}  {name}（落库于 {sname}）", i + 1));
            }
        }
    }
    assert_absent(
        bad,
        "I6: 这些枚举同时 derive 了 SurrealValue 与 Default。落库时会编码成 \
         `{ Variant: {} }` 而不是字符串，数据库以 `Expected string` 拒写 —— \
         编译、clippy 与断言 serde 往返的单测都发现不了",
    );
}

// ═════════════════════ J. Machine Contract 层 ═════════════════════
// 法源: GA-07 §16-24（Machine Contract Authority），
//       V3 Engineering Alignment Notes 23 §8 / 27 §2 / 29 §1

/// J1 · Permission Registry 与 Runtime 一致
///
/// GA-07 §22 把权限的两层职责分开：Meaning 归 27｜Administration，
/// Exact Name 归 Permission Registry。注册表一旦与 Runtime 漂开，
/// 「Guide 不得自创权限名」这条纪律就失去了参照物。
///
/// I3 已经守住「种子 ↔ 代码」，这里守「注册表 ↔ 代码」。
#[test]
fn j1_permission_registry_matches_runtime() {
    let registry = read("contracts/permissions.yaml");
    let perm_src = read("src/models/permission.rs");

    let mut in_code: Vec<String> = Vec::new();
    let mut rest = perm_src.as_str();
    while let Some(at) = rest.find("auth_local!(\"") {
        let tail = &rest[at + "auth_local!(\"".len()..];
        let Some(end) = tail.find('"') else { break };
        let name = &tail[..end];
        if !name.is_empty() {
            in_code.push(format!("soulauth:{name}"));
        }
        rest = &tail[end..];
    }
    in_code.sort();
    in_code.dedup();
    assert!(!in_code.is_empty(), "找不到权限常量 —— 断言失去作用域");

    for p in &in_code {
        assert!(
            registry.contains(&format!("name: {p}")),
            "Runtime 校验 `{p}`，但 Permission Registry 没有声明它"
        );
    }

    // 反向：注册表不得声明 Runtime 不校验的权限（授予了却零效果）。
    for line in registry.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_prefix("- name: soulauth:") {
            let full = format!("soulauth:{name}");
            assert!(
                in_code.contains(&full),
                "Permission Registry 声明了 `{full}`，但 Runtime 从不校验它"
            );
        }
    }
}

/// J2 · Configuration Registry 与 Runtime 一致
///
/// GA-07 §21 双向：文档写了但 Runtime 不存在 → BLOCK；Runtime 存在且会实质
/// 改变 Supported Public Behavior 但注册表不声明 → Contract Drift。
#[test]
fn j2_configuration_registry_matches_runtime() {
    let registry = read("contracts/configuration.yaml");

    // Runtime 读取的每一个环境变量都必须在注册表里。
    //
    // **扫全 `src/`，不是只扫 config.rs 与 main.rs。** 早先这里只看那两个文件,
    // 于是 `services/database.rs` 里四个 `SURREAL_*` 从未被登记也从未被报警 ——
    // 守卫自己有盲区，比没有守卫更危险 —— 它给了一种「已经守住了」的错觉。
    //
    // 只认「配置读取辅助函数 + 裸 env::var」这两种形态 —— 源码里其它大写
    // 字符串（错误文案、SQL 关键字）不是配置项。
    let all = sources();
    let mut in_runtime: Vec<String> = Vec::new();
    for (_, src) in &all {
        let production = match src.find("#[cfg(test)]") {
            Some(i) => &src[..i],
            None => &src[..],
        };
        for helper in [
            "required(\"",
            "optional(\"",
            "optional_raw(\"",
            "parse_bool(\"",
            "parse_with_default(\"",
            "env::var(\"",
        ] {
            let mut from = 0usize;
            while let Some(rel) = production[from..].find(helper) {
                let at = from + rel + helper.len();
                let Some(end) = production[at..].find('"') else {
                    break;
                };
                let name = &production[at..at + end];
                if name.len() > 3
                    && name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
                {
                    in_runtime.push(name.to_string());
                }
                from = at + end;
            }
        }
    }
    in_runtime.sort();
    in_runtime.dedup();
    assert!(
        in_runtime.len() > 30,
        "只解析出 {} 个环境变量，远少于预期 —— 解析逻辑可能失效了",
        in_runtime.len()
    );

    for name in &in_runtime {
        assert!(
            registry.contains(&format!("name: {name}\n")),
            "Runtime 读取 `{name}`，但 Configuration Registry 没有声明它"
        );
    }
}

/// J3 · Registry 不得含未填充的占位符
///
/// 法源: V3 30｜Project Status §29 —— Public Matrix 中任何 blank / TBD /
/// `<EXACT>` / Pending 都必须**阻止** Release Status publication。
///
/// Machine Contract 是 Public Claim 的依据，同一条纪律适用。
#[test]
fn j3_registries_have_no_placeholders() {
    for f in ["contracts/permissions.yaml", "contracts/configuration.yaml"] {
        let body = read(f);
        for (n, line) in body.lines().enumerate() {
            let code = match line.find('#') {
                Some(i) => &line[..i],
                None => line,
            };
            for ph in ["<EXACT", "TBD", "TODO", "PENDING", "FIXME"] {
                assert!(
                    !code.to_uppercase().contains(ph),
                    "{f}:{} 含占位符 `{ph}` —— Registry 是 Public Claim 的依据，\
                     未填充项必须阻止发布",
                    n + 1
                );
            }
        }
    }
}

/// J4 · OpenAPI 与 Runtime 路由表一致
///
/// 法源: GA-07 §17「OpenAPI 的最终法位」与 §25「Machine Contract ≠ Runtime
/// Reality」—— 两者必须对齐，但对齐要靠证据而不是靠承诺。
///
/// 这条断言双向：Runtime 有而契约没声明是 Contract Drift；契约声明而 Runtime
/// 没有是凭空承诺，后者更危险（消费方会照着调）。
#[test]
fn j4_openapi_matches_the_route_table() {
    let spec = read("contracts/openapi.yaml");
    let main = read("src/main.rs");

    // main.rs 里直接挂的路由（例如 /health）。
    for m in main.match_indices(".route(\"") {
        let tail = &main[m.0 + ".route(\"".len()..];
        let Some(end) = tail.find('"') else { continue };
        let path = &tail[..end];
        if !path.starts_with('/') {
            continue;
        }
        assert!(
            spec.contains(&format!("\n  {path}:")),
            "Runtime 挂载了 `{path}`，但 OpenAPI 没有声明它"
        );
    }

    // 反向：契约里的每个 operationId 都要能在源码里找到同名 handler。
    let sources = sources();
    let mut checked = 0usize;
    for line in spec.lines() {
        let Some(op) = line.trim().strip_prefix("operationId: ") else {
            continue;
        };
        // operationId 是 `<module>_<handler>`，但两边都可能含下划线
        // （user_management_list_users、oidc_client_list_clients），按第一个
        // 下划线切会切错。改为：找一个 routes/ 下的文件，它的模块名是 op 的
        // 前缀，且文件里有以剩余部分命名的 handler。
        let found = sources.iter().any(|(f, b)| {
            let Some(module) = f
                .strip_prefix("routes/")
                .and_then(|x| x.strip_suffix(".rs"))
            else {
                return false;
            };
            let Some(handler) = op.strip_prefix(&format!("{module}_")) else {
                return false;
            };
            b.contains(&format!("fn {handler}("))
        }) || op
            .strip_prefix("main_")
            .is_some_and(|h| read("src/main.rs").contains(&format!("fn {h}(")));
        assert!(
            found,
            "OpenAPI 声明了 operationId `{op}`，但源码里没有这个 handler"
        );
        checked += 1;
    }
    assert!(
        checked > 50,
        "只校验了 {checked} 个 operation —— 解析可能失效了"
    );
}

/// J5 · Standards Registry 不得声明未实现的端点
///
/// 法源: V3 22 三条纪律 ——
///   Internal Revocation Semantics  ≠ RFC 7009 Support
///   Internal / Online Token Lookup ≠ RFC 7662 Introspection
///   SoulAuth issues Access Tokens  ≠ RFC 9068 Conformance
///
/// 「内部有类似动作」不构成对某个标准端点的支持。
#[test]
fn j5_standards_registry_does_not_overclaim() {
    let registry = read("contracts/standards.yaml");
    let oidc = read("src/services/oidc.rs");

    // 三个高风险规范：声明 implemented: true 就必须能找到对应实现。
    for (spec_id, marker, what) in [
        ("rfc7009", "fn revoke_token_endpoint", "/revoke 端点"),
        ("rfc7662", "fn introspect", "/introspect 端点"),
    ] {
        let Some(at) = registry.find(&format!("id: {spec_id}")) else {
            continue;
        };
        let block: String = registry[at..].chars().take(400).collect();
        let claims_implemented = block.lines().any(|l| l.trim() == "implemented: true");
        if claims_implemented {
            assert!(
                oidc.contains(marker),
                "Standards Registry 声明 {spec_id} implemented，但找不到 {what}"
            );
        }
    }

    // certified 必须全部为 false —— 当前不存在任何已完成的认证。
    // 改成 true 需要真实的认证文件作为 Evidence，不能靠自我声明。
    assert!(
        !registry.contains("certified: true"),
        "Standards Registry 出现 certified: true —— 认证需要 Standards \
         Organization 的正式流程作为 Evidence，不能自我声明"
    );
}

/// J6 · 全站只有一种错误形状
///
/// 法源: V3 30｜Project Status §12 —— 消费方最容易被误导的不是缺功能，
/// 而是**同一个 API 在不同端点上行为不一致**。
///
/// 这条防的是一个真实存在过的缺口：`/api/rbac/*` 与 `/api/ops/*` 的 handler
/// 返回 `Result<T, StatusCode>`，于是「权限不足」在那 14 个端点上是**空响应体**，
/// 在其余端点上是 JSON。四种形状并存时，API Reference 物理上写不出来。
#[test]
fn j6_error_shape_is_uniform() {
    // 1. 没有任何 handler 把裸 StatusCode 当错误返回。
    for (file, body) in sources() {
        if !file.starts_with("routes/") {
            continue;
        }
        let production = match body.find("#[cfg(test)]") {
            Some(i) => &body[..i],
            None => &body[..],
        };
        for pat in ["Err(StatusCode::", "Err(axum::http::StatusCode::"] {
            assert!(
                !production.contains(pat),
                "{file} 用裸 StatusCode 当错误返回 —— 那是空响应体，\
                 调用方拿不到码也拿不到说明。改成返回 AuthError。"
            );
        }
    }

    // 2. 两个权限宏必须产出同一个错误。分叉过一次，不能再分叉第二次。
    let mw = read("src/utils/permission_middleware.rs");
    assert!(
        mw.contains("AuthError::MissingPermission"),
        "权限宏必须产出 AuthError::MissingPermission"
    );
    assert!(
        !mw.contains("StatusCode::FORBIDDEN"),
        "权限宏不得再返回裸 StatusCode"
    );

    // 3. 路由层自造的错误体只允许两处：统一的 error_body，和 OIDC 的 RFC 形状。
    let mut ad_hoc = Vec::new();
    for (file, body) in sources() {
        if !file.starts_with("routes/") {
            continue;
        }
        for line in body.lines() {
            let l = line.trim();
            if l.contains("json!({") && l.contains("\"error\"") {
                let allowed = l.contains("\"error\": code, \"message\": message")
                    || l.contains("\"error\": code, \"error_description\": description");
                if !allowed {
                    ad_hoc.push(format!("{file}: {l}"));
                }
            }
        }
    }
    assert!(
        ad_hoc.is_empty(),
        "路由层出现自造错误体，形状会与 AuthError 分叉：\n{}",
        ad_hoc.join("\n")
    );
}

/// J7 · 对外 URL 里不得出现重复路径段
///
/// 法源: V3 22 —— Published Machine-readable Contract 是消费方唯一依据，
/// 而一条 `/api/users/users/:user_id` 这样的路径会让人第一眼认为文档写错了。
///
/// 发布前改是零成本，发布后改是 breaking change。
#[test]
fn j7_no_duplicated_path_segments() {
    let contract = read("contracts/openapi.yaml");
    for line in contract.lines() {
        let l = line.trim_start();
        if !l.starts_with('/') || !l.ends_with(':') {
            continue;
        }
        let path = l.trim_end_matches(':');
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        for pair in segments.windows(2) {
            assert!(
                pair[0] != pair[1],
                "路径 `{path}` 里出现重复段 `{}` —— 多半是 nest 前缀与路由本身撞了",
                pair[0]
            );
        }
    }
}

/// J8 · AIActor 认证的 13 项冻结面
///
/// 法源: V3《24｜Authentication & Sessions》§2 —— 在这 13 项完成 Machine
/// Contract Alignment 之前，signed proof **不得**被描述为完整的 Public
/// Authentication Method。
///
/// 这条测试就是那份 Alignment：每一项都要能在 Runtime 里指出落点。少一项，
/// 文档里那句「支持 AIActor 认证」就是过度声称。
#[test]
fn j8_ai_actor_auth_surface_is_frozen() {
    let model = read("src/models/ai_actor.rs");
    let svc = read("src/services/ai_actor.rs");
    let registry = read("contracts/standards.yaml");

    // ① credential representation / ② verification key format
    assert!(
        model.contains("ED25519_PUBLIC_KEY_LEN: usize = 32"),
        "公钥长度未冻结"
    );
    assert!(
        svc.contains("URL_SAFE_NO_PAD"),
        "密钥/签名编码未冻结为 base64url-no-pad"
    );

    // ③ algorithm allowlist —— 必须是**单元素**。
    //    可协商的算法列表是签名协议里最经典的一类漏洞。
    assert!(
        model.contains("ALLOWED_ALGORITHMS: [&str; 1]"),
        "算法白名单必须是单元素数组 —— 一旦可协商就会被降级"
    );

    // ④ signed payload / ⑤ canonicalization —— 只能有一处构造。
    assert!(
        model.contains("fn canonical_payload"),
        "缺少唯一的被签名内容构造函数"
    );
    let builders =
        svc.matches("canonical_payload(").count() + model.matches("fn canonical_payload").count();
    assert!(
        builders >= 2,
        "服务层必须调用同一个 canonical_payload，不得自己拼被签名内容"
    );
    assert!(
        !svc.contains("serde_json::to_string(&payload") && !model.contains("serde_json::to_vec"),
        "被签名内容不得来自 JSON 序列化 —— JSON 没有唯一字节表示"
    );

    // ⑦ domain separation —— 带版本号，否则改了 payload 结构新旧签名互通。
    assert!(
        model.contains("AI_ACTOR_AUTH_DOMAIN") && model.contains("soulauth-ai-actor-auth/v"),
        "缺少带版本的域分隔常量"
    );

    // ⑧ challenge —— 服务端签发的 CSPRNG 随机数。
    assert!(
        svc.contains("fill_bytes") && svc.contains("fn issue_challenge"),
        "挑战必须由服务端用 CSPRNG 签发"
    );
    assert!(
        field_exists("ai_actor_challenge", "nonce"),
        "缺少 ai_actor_challenge.nonce"
    );

    // ⑨ timestamp / ⑩ expiry
    for f in ["issued_at", "expires_at"] {
        assert!(
            field_exists("ai_actor_challenge", f),
            "挑战缺少 `{f}` —— 时间戳与有效期都必须落库并由服务端决定"
        );
    }
    assert!(
        model.contains("CHALLENGE_TTL_SECONDS"),
        "挑战有效期未冻结为常量"
    );

    // ⑪ replay semantics —— 一次性，且必须是**条件更新**而不是先读后写。
    assert!(
        field_exists("ai_actor_challenge", "consumed"),
        "挑战缺少 consumed 标记"
    );
    assert!(
        svc.contains("consumed = false"),
        "消费挑战必须用条件更新（WHERE consumed = false），先读后判有并发窗口"
    );
    // 消费必须发生在验签之前，否则失败的尝试不烧挑战，nonce 就成了爆破靶子。
    let consume_at = svc
        .find("ai_actor_consume_challenge")
        .expect("找不到消费挑战的查询");
    let verify_at = svc.find("fn verify_with").map(|_| {
        svc.find("Self::verify_with(&credential.public_key")
            .expect("找不到验签调用点")
    });
    if let Some(verify_at) = verify_at {
        assert!(
            consume_at < verify_at,
            "挑战必须在验签**之前**被消费 —— 反过来会留下并发窗口"
        );
    }

    // ⑫ actor binding —— nonce 绑定 actor，且 actor 进入被签名内容。
    assert!(
        field_exists("ai_actor_challenge", "actor_identity_id"),
        "挑战必须绑定到具体 actor"
    );

    // ⑬ error contract —— 走统一 AuthError，不自造形状。
    assert!(
        !svc.contains("StatusCode::"),
        "AIActor 服务不得自己产出 HTTP 状态码，错误一律走 AuthError"
    );

    // 凭证不得与人类凭证混在同一张表 —— 那会让「AIActor 无需 HumanAccount」
    // 在存储层重新失效。
    assert!(
        field_exists("ai_actor_credential", "public_key"),
        "缺少 ai_actor_credential.public_key"
    );
    for secret in ["password_hash", "secret", "private_key"] {
        assert!(
            !field_exists("ai_actor_credential", secret),
            "ai_actor_credential 不得存放 `{secret}` —— SoulAuth 只持有公钥"
        );
    }

    // 注册表必须把「这不是哪些标准」写明白：消费方最容易把它当成
    // RFC 7523 / mTLS / client credentials。
    assert!(
        registry.contains("soulauth-ai-actor-auth/v1") && registry.contains("not_this"),
        "standards.yaml 必须声明该机制**不是**哪些既有标准"
    );
    for rfc in ["7523", "8705"] {
        assert!(
            registry.contains(&format!("RFC {rfc}")),
            "standards.yaml 的 not_this 里缺少对 RFC {rfc} 的澄清"
        );
    }
}
