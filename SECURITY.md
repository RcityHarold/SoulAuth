# Security

## 报告漏洞

请不要用公开 issue 报告安全问题。发邮件到项目维护者，或使用 GitHub 的
private vulnerability reporting。请附上复现步骤——一个能跑的复现比一段描述
有用得多。

## 已知的依赖公告，以及为什么它们在本项目里不可达

`cargo audit` 目前会报 7 条。它们全部来自传递依赖或用法之外的 API。
逐条给出判断依据，这样你不必自己重做一遍分析：

| 依赖 | 公告 | 为什么不影响 SoulAuth |
|---|---|---|
| `rsa 0.9` | RUSTSEC-2023-0071（Marvin 时序侧信道）| **无修复版本，且短期不会有。** 该攻击针对 PKCS#1 v1.5 **解密**。本项目只把 `rsa` 当作 PEM/DER 编解码器（读私钥、导出 JWKS 的 n/e），RS256 的**签名运算由 `jsonwebtoken` 经 `ring` 完成**，`rsa` 全程不执行任何私钥数学运算。 |
| `ring 0.16` | RUSTSEC-2025-0009 | 受影响的是 `ring::aead::quic::HeaderProtectionKey`。本项目不使用 QUIC。 |
| `ring 0.16` | RUSTSEC-2025-0010（未维护）| 同上；由 `jsonwebtoken 8` 传递引入。 |
| `idna 0.4` | RUSTSEC-2024-0421（punycode 混淆标签）| redirect_uri 采用**精确字符串比较**，不做 URL 归一化或 IDNA 处理，构不成回跳绕过。邮箱域名校验也是纯字符串检查。 |
| `rkyv 0.7` | RUSTSEC-2026-0235 | SurrealDB 的传递依赖，本项目不直接使用其序列化路径。 |
| `atomic-polyfill` | RUSTSEC-2023-0089（未维护）| 传递依赖。 |
| `proc-macro-error` | RUSTSEC-2024-0370（未维护）| 编译期依赖，不进入运行时。 |

### 为什么不升级 `axum` / `jsonwebtoken` 来清掉 `ring 0.16`

`ring 0.16` 由 `jsonwebtoken 8` 引入，`hyper 0.14` 由 `axum 0.6` 引入。
升级要跨 axum 0.6→0.8（`Server` 移除、`TypedHeader` 迁出、提取器改动）与
jsonwebtoken 8→10，而上表已说明这两条公告在本项目里不可达。
改动风险大于收益，因此这是一个**有意识的选择**，不是遗漏。
若你的合规流程要求 `cargo audit` 零命中，可以用 `cargo audit --ignore` 配合上表。

## 已知限制

- **数据库连接只支持 root 身份。** 代码走 `surrealdb::opt::auth::Root`，
  没有 namespace / database 级登录的分支。最小权限数据库账号是待办项。
  在它落地前，请让 SurrealDB 只监听内网、口令不复用、跨网段用 `https://`。
- **注册接口会因重复邮箱返回 409**，因此可以探测某个邮箱是否已注册。
  密码重置与重发验证信刻意不这样做（一律静默 200）。这是可用性与
  防枚举之间的一次取舍，不是疏漏。
- **ID Token 有效期硬性上限 300 秒**，对所有客户端一律生效。
  Phase 0 不提供 RFC 7662 introspection，接入方在令牌有效期内感知不到吊销。
