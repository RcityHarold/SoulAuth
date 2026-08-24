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
                    .unwrap_or_else(|_| path.as_path())
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
#[ignore = "V2 Stage 1 —— user 一张表同时是登录主体/Profile/商业状态/权限载体"]
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
#[ignore = "V2 Stage 1/2 —— SubjectType::Agent 六个创建点全写死 Human，从未被构造"]
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
/// 存在一条不需要 email / username / password 的认证路径。
#[test]
#[ignore = "V2 Stage 2 —— 无 AIActor 认证路径，建非人主体只能去注册一个 user"]
fn a6_ai_actor_needs_no_human_account() {
    let has_path = sources()
        .iter()
        .any(|(f, _)| f.contains("ai_actor_auth") || f.contains("actor_assertion"));
    assert!(
        has_path,
        "缺少 AIActor 原生认证路径（RFC 7523 JWT Bearer Assertion）"
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
#[ignore = "V2 Stage 3 —— oidc_refresh_token.token 与 oidc_authorization_code.code 仍是明文"]
fn b4b_bearer_secrets_are_not_stored_in_clear() {
    assert!(
        !field_exists("oidc_refresh_token", "token"),
        "refresh token 不得明文存储，应存 hash"
    );
    assert!(
        !field_exists("oidc_authorization_code", "code"),
        "authorization code 不得明文存储，应存 digest"
    );
    // 轮换与重放检测必须是正式 Token Lifecycle，不是散落的业务逻辑。
    for f in ["token_family", "reuse_detected_at"] {
        assert!(
            field_exists("oidc_refresh_token", f),
            "refresh token 缺少 lifecycle 字段 `{f}`"
        );
    }
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
/// 同级目录不存在时跳过——文档仓库/CI 可以独立构建。
#[test]
fn e4_consumers_do_not_read_the_database() {
    let adapter = root().join("../SoulSeedOS/crates/adapters/soulseed-adapter-soulauth/src");
    if !adapter.exists() {
        eprintln!("跳过 E4：未找到 OS 适配器（跨仓，非本仓构建前提）");
        return;
    }
    let mut bodies = Vec::new();
    walk(&adapter, &adapter, &mut bodies);
    for (file, body) in bodies {
        for forbidden in ["surrealdb", "Surreal::", "DATABASE_URL"] {
            assert!(
                !body.contains(forbidden),
                "适配器 {file} 出现 `{forbidden}` —— 消费方不得直连 SoulAuth 数据库"
            );
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
#[test]
#[ignore = "V2 Stage 5 —— 尚无 canonical_actor_ref，该不变式在绑定落地后才可测"]
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
/// `code` 是契约，`message` 可以变。调用方按状态码和 code 匹配，不按文案匹配。
#[test]
#[ignore = "V2 Stage 6 —— 四种错误形状并存，且无机器可读 code"]
fn g3_error_contract_is_stable() {
    let err = read("src/error.rs");
    assert!(
        err.contains("\"code\""),
        "非 OIDC API 的错误体必须携带稳定的机器可读 `code`"
    );
}
