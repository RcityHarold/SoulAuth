#!/usr/bin/env bash
#
# SoulAuth 端到端集成测试
#
# 为什么是脚本而不是 `cargo test`：
#   本套用例需要一个真实的 SurrealDB 与一个真实运行的服务进程。把它挂进
#   `cargo test` 会让原本 5 秒、零外部依赖的单元测试变成「必须装 surreal、
#   必须有空闲端口」，那是倒退。两者分工：
#     cargo test        —— 纯逻辑与一致性断言，随时可跑
#     tests/integration.sh —— 契约级行为，改完动真格的时候跑
#
# 用法：
#   cargo build && ./tests/integration.sh
#   SURREAL_PORT=8101 APP_PORT=8180 SINK_PORT=8125 ./tests/integration.sh   # 端口被占时
#   KEEP_WORK=1 ./tests/integration.sh                       # 失败时保留现场
#
# 退出码：0 全过；1 有断言失败；2 前置条件不满足。

set -uo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SURREAL_PORT="${SURREAL_PORT:-8101}"
readonly APP_PORT="${APP_PORT:-8180}"
# 用 SINK_PORT 而不是 SMTP_PORT：后者是应用要读的环境变量名，
# 脚本里若把它声明成 readonly，start_app 的命令前缀赋值会被拒
# （bash: "SMTP_PORT: readonly variable"），应用于是回落到默认端口，
# 信发到没人听的地方 —— 而发信失败只记日志，故障完全静默。
readonly SINK_PORT="${SINK_PORT:-8125}"
readonly OAUTH_PORT="${OAUTH_PORT:-8127}"
readonly DB="http://127.0.0.1:${SURREAL_PORT}"
readonly APP="http://127.0.0.1:${APP_PORT}"
readonly WORK="$(mktemp -d)"

# 本机环境常有全局 HTTP 代理，会把 127.0.0.1 的请求也代理走。
export no_proxy="localhost,127.0.0.1" NO_PROXY="localhost,127.0.0.1"

readonly NL=$'\n'

PASS=0
FAIL=0
DB_PID=""
APP_PID=""
SINK_PID=""
MOCK_PID=""

# ───────────────────────────────── 输出 ─────────────────────────────────

c_grn() { printf '\033[32m%s\033[0m' "$1"; }
c_red() { printf '\033[31m%s\033[0m' "$1"; }
c_dim() { printf '\033[2m%s\033[0m' "$1"; }

group() { printf '\n%s\n' "── $* ──"; }

ok()   { PASS=$((PASS+1)); printf '  %s %s\n' "$(c_grn ✓)" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  %s %s\n' "$(c_red ✗)" "$1"
         [ $# -gt 1 ] && printf '      %s\n' "$(c_dim "$2")"; return 0; }

# 断言：期望值 实际值 描述
eq() {
    # 取值里出现换行，几乎都意味着取值逻辑坏了（典型：`grep -c ... || echo 0`
    # 会输出两行）。若不拦下来，调用方一旦把它送进 $(( )) 就是语法错，
    # 整条断言连同它的结果一起消失，汇总还会显示"全部通过"。
    # 用 $'\n' 字面量，不能用 "$(printf '\n')" —— 命令替换会剥掉尾部换行，
    # 那样模式退化成 `**`，匹配一切，每条断言都会被误判。
    case "$1$2" in
        *"$NL"*) bad "$3" "取值含换行，说明取值逻辑有误：期望 [$1] 实际 [$2]"; return ;;
    esac
    if [ "$1" = "$2" ]; then ok "$3"; else bad "$3" "期望 [$1]，实际 [$2]"; fi
}

# 断言：实际值中应包含子串
has() {
    case "$2" in
        *"$1"*) ok "$3" ;;
        *)      bad "$3" "未找到 [$1]，实际 [${2:0:120}]" ;;
    esac
}

# ───────────────────────────── HTTP / SQL 助手 ─────────────────────────────

# 发请求，回显 HTTP 状态码；响应体写入 $WORK/body
req() {
    local method="$1" path="$2"; shift 2
    curl -sS --max-time 25 -o "$WORK/body" -w '%{http_code}' \
        -X "$method" "${APP}${path}" "$@" 2>/dev/null || echo "000"
}
body() { cat "$WORK/body" 2>/dev/null; }

# 从响应体里取一个 JSON 字段（支持 data 包一层的情况）
jget() {
    python3 -c "
import json,sys
try: d=json.load(open('$WORK/body'))
except Exception: print(''); sys.exit()
b=d.get('data') if isinstance(d,dict) and isinstance(d.get('data'),dict) else d
print(b.get('$1','') if isinstance(b,dict) else '')" 2>/dev/null
}

# 直连数据库执行 SQL，回显首条语句的 result（JSON）
sql() {
    curl -sS --max-time 15 -u root:root \
        -H 'Accept: application/json' -H 'surreal-ns: auth' -H 'surreal-db: main' \
        --data "$1" "${DB}/sql" 2>/dev/null |
    python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)[0]['result']))" 2>/dev/null
}

# 取聚合计数（GROUP ALL 的查询）
sql_count() {
    # 兜底放在 python 内部，不用 `|| echo 0` —— 那样在 python 已经输出过
    # 内容的情况下会叠加成两行，调用方的算术展开直接语法错。
    sql "$1" | python3 -c "
import json,sys
try:
    r = json.load(sys.stdin)
    print(r[0].get('count', r[0].get('total', 0)) if r else 0)
except Exception:
    print(0)" 2>/dev/null
}

# ───────────────────────────── 邮件助手 ─────────────────────────────
#
# 信件是 quoted-printable 编码的：`=3D` 表示 `=`，行尾单个 `=` 是软换行，
# token 会被拦腰截断（`token=3D3b=\nf12ff5-...`）。所以**不能**拿正则去啃
# 原始 SMTP 数据，必须先解码。这里用标准库 email 模块，顺带把 base64 和
# 字符集一并处理掉。

MAILBOX=""

# 注意：`grep -c` 无匹配时会打印 0 **并且**退出码为 1。写成
# `grep -c ... || echo 0` 会打印两个 0，调用方拿到 "0\n0"，
# 于是 $((BEFORE + 1)) 直接语法错 —— 断言不是失败，而是**静默消失**，
# 汇总还照样说"全部通过"。grep -c 本来就总会输出数字，不需要兜底。
mail_count() {
    [ -f "$MAILBOX" ] || { echo 0; return; }
    grep -c '===MAIL===' "$MAILBOX" 2>/dev/null
}

# 最后一封信的解码正文
mail_body() {
    python3 -c "
import email, sys
parts = open('$MAILBOX', encoding='utf-8', errors='replace').read().split('===MAIL===')
if len(parts) < 2: sys.exit()
msg = email.message_from_string(parts[-1].strip())
payload = msg.get_payload(decode=True)
print(payload.decode('utf-8', 'replace') if payload else '')" 2>/dev/null
}

# 最后一封信的某个头
mail_header() {
    python3 -c "
import email, sys
parts = open('$MAILBOX', encoding='utf-8', errors='replace').read().split('===MAIL===')
if len(parts) < 2: sys.exit()
print(email.message_from_string(parts[-1].strip()).get('$1', ''))" 2>/dev/null
}

# ───────────────────────────── 生命周期 ─────────────────────────────

cleanup() {
    [ -n "$SINK_PID" ] && kill -9 "$SINK_PID" 2>/dev/null
    [ -n "$MOCK_PID" ] && kill -9 "$MOCK_PID" 2>/dev/null
    [ -n "$APP_PID" ] && kill -9 "$APP_PID" 2>/dev/null
    [ -n "$DB_PID" ]  && kill -9 "$DB_PID"  2>/dev/null
    # 排查时用 KEEP_WORK=1 保留现场（服务日志、信箱、最后一次响应体）
    if [ -n "${KEEP_WORK:-}" ]; then
        printf '\n现场保留在 %s\n' "$WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

wait_for() {
    local url="$1" name="$2" n=0
    while [ $n -lt 40 ]; do
        [ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null)" != "000" ] && return 0
        sleep 0.5; n=$((n+1))
    done
    printf '%s %s 未能在 20 秒内就绪\n' "$(c_red ✗)" "$name"; return 1
}

start_db() {
    surreal start --bind "127.0.0.1:${SURREAL_PORT}" --user root --pass root memory \
        > "$WORK/surreal.log" 2>&1 &
    DB_PID=$!
    disown "$DB_PID" 2>/dev/null
    wait_for "${DB}/health" "SurrealDB" || exit 2
    for f in schema.sql initial_data.sql; do
        surreal import --endpoint "$DB" --user root --pass root \
            --namespace auth --database main "$ROOT/$f" > "$WORK/import.log" 2>&1 ||
            { printf '%s 导入 %s 失败\n' "$(c_red ✗)" "$f"; cat "$WORK/import.log"; exit 2; }
    done
}

# 启动服务。限流计数保存在进程内存里，重启即清零 ——
# 注册 3 次/5 分钟、登录 5 次/5 分钟，用例超过这个量必须重启，
# 否则后续断言全被 429 污染，看起来像功能坏了。
start_app() {
    (
        cd "$ROOT"
        DATABASE_URL="127.0.0.1:${SURREAL_PORT}" \
        DATABASE_USER=root DATABASE_PASS=root \
        DATABASE_NAMESPACE=auth DATABASE_NAME=main \
        JWT_SECRET=0123456789abcdef0123456789abcdef \
        GOOGLE_CLIENT_ID=dummy GOOGLE_CLIENT_SECRET=dummy \
        GITHUB_CLIENT_ID=dummy GITHUB_CLIENT_SECRET=dummy \
        OAUTH_REDIRECT_URL="${APP}/api/auth/callback" \
        SMTP_HOST=127.0.0.1 SMTP_PORT="${SINK_PORT}" SMTP_FROM=noreply@example.com \
        SMTP_INSECURE=true \
        APP_URL="$APP" EMAIL_VERIFICATION_ENABLED="${VERIFY_EMAIL:-false}" \
        GOOGLE_OAUTH_BASE_URL="${OAUTH_BASE:-}" \
        GITHUB_OAUTH_BASE_URL="${OAUTH_BASE:-}" \
        BIND_ADDR="127.0.0.1:${APP_PORT}" \
        RUST_LOG=rust_auth=warn \
        exec ./target/debug/rust-auth
    ) > "$WORK/app.log" 2>&1 &
    APP_PID=$!
    disown "$APP_PID" 2>/dev/null   # 免得 kill -9 时 shell 打一行 "Killed ..." 混进输出
    wait_for "${APP}/api/oidc/jwks" "SoulAuth" || { cat "$WORK/app.log"; exit 2; }
}

restart_app() {
    kill -9 "$APP_PID" 2>/dev/null
    sleep 0.5
    start_app
}

# 注册并登录，回显访问令牌
signup() {
    req POST /api/auth/register -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"password\":\"CorrectHorse42!\",\"username\":\"$2\"}" > /dev/null
    jget id > "$WORK/uid_$2"   # register 返回 {token,user:{id}}，此处取不到就靠下面的 login
    req POST /api/auth/login -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"password\":\"CorrectHorse42!\"}" > /dev/null
    jget token
}

user_id_of() {
    sql "SELECT VALUE type::string(id) FROM user WHERE email = '$1' LIMIT 1" |
        python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0].split(':',1)[1].strip('\`') if r else '')" 2>/dev/null
}

grant_admin() {
    sql "CREATE user_role CONTENT { user_id: type::record('user','$1'), role_id: role:admin,
         assigned_at: 0, assigned_by: user:system }" > /dev/null
}

# ───────────────────────────── 前置检查 ─────────────────────────────

command -v surreal > /dev/null || { echo "缺少 surreal 可执行文件"; exit 2; }
command -v python3 > /dev/null || { echo "缺少 python3"; exit 2; }
[ -x "$ROOT/target/debug/rust-auth" ] || { echo "请先 cargo build"; exit 2; }
for p in "$SURREAL_PORT" "$APP_PORT" "$SINK_PORT" "$OAUTH_PORT"; do
    if ss -ltn 2>/dev/null | grep -q ":${p} "; then
        echo "端口 ${p} 已被占用；可用 SURREAL_PORT / APP_PORT / SINK_PORT / OAUTH_PORT 覆盖"; exit 2
    fi
done

printf 'SoulAuth 集成测试  db=:%s  app=:%s\n' "$SURREAL_PORT" "$APP_PORT"
start_db
start_app

# ═══════════════════════════════ 用例 ═══════════════════════════════

group "1. 服务与发现端点"

eq 200 "$(req GET /api/oidc/jwks)" "GET /api/oidc/jwks"
has '"kty":"RSA"' "$(body)" "JWKS 含 RSA 公钥"
has '"kid"' "$(body)" "JWKS 含 kid"

eq 200 "$(req GET /api/oidc/.well-known/openid-configuration)" "OIDC 发现文档"
has '"RS256"' "$(body)" "ID Token 签名算法宣告为 RS256"
has '"S256"' "$(body)" "PKCE 只宣告 S256"

group "2. 注册 / 登录 / 会话"

ADMIN_TOKEN="$(signup admin@test.local admintest)"
[ -n "$ADMIN_TOKEN" ] && ok "注册并登录成功" || bad "注册并登录成功" "未取到令牌"

eq 200 "$(req GET /api/auth/me -H "Authorization: Bearer $ADMIN_TOKEN")" "GET /api/auth/me"
has 'admin@test.local' "$(body)" "/me 返回本人邮箱"

# RFC 7235：认证方案名不区分大小写
eq 200 "$(req GET /api/auth/me -H "authorization: bearer $ADMIN_TOKEN")" "小写 bearer 同样被接受"
eq 401 "$(req GET /api/auth/me -H "authorization: Basic $ADMIN_TOKEN")" "Basic 方案被拒绝"
eq 401 "$(req GET /api/auth/me)" "无令牌 401"

group "3. 权限名前缀与 RBAC 守卫"

ADMIN_UID="$(user_id_of admin@test.local)"
grant_admin "$ADMIN_UID"

PERM_SAMPLE="$(sql "SELECT VALUE name FROM permission LIMIT 1" | python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else '')")"
has 'soulauth:' "$PERM_SAMPLE" "库内权限名带 soulauth: 前缀"

UNPREFIXED="$(sql_count "SELECT count() FROM permission WHERE !string::starts_with(name,'soulauth:') GROUP ALL")"
eq 0 "$UNPREFIXED" "无未加前缀的残留权限"

eq 200 "$(req GET /api/rbac/roles -H "Authorization: Bearer $ADMIN_TOKEN")"          "管理员可读角色（soulauth:roles.read）"
eq 200 "$(req GET '/api/users/users?limit=2' -H "Authorization: Bearer $ADMIN_TOKEN")" "管理员可读用户（soulauth:users.read）"
eq 200 "$(req GET '/api/audit/dashboard?days=1' -H "Authorization: Bearer $ADMIN_TOKEN")" "管理员可读审计（soulauth:audit.read）"
eq 200 "$(req GET /api/oidc/clients -H "Authorization: Bearer $ADMIN_TOKEN")"        "管理员可读 OIDC 客户端"

PLAIN_TOKEN="$(signup plain@test.local plaintest)"
eq 403 "$(req GET /api/users/users -H "Authorization: Bearer $PLAIN_TOKEN")" "无权限用户被拒"
has 'soulauth:users.read' "$(body)" "拒绝信息里带命名空间前缀"

group "4. RBAC 授予与撤销的往返"

req POST /api/rbac/roles -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d '{"name":"itest","display_name":"IT","description":"d"}' > /dev/null
req POST /api/rbac/permissions -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    -d '{"name":"soulauth:itest.read","display_name":"ITR","resource":"itest","action":"read"}' > /dev/null

eq 200 "$(req POST /api/rbac/roles/itest/permissions/assign -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' -d '{"permission_name":"soulauth:itest.read"}')" "给角色授权限"
eq 1 "$(sql_count "SELECT count() FROM role_permission WHERE role_id IN (SELECT VALUE id FROM role WHERE name='itest') GROUP ALL")" \
    "授权确实落库"

eq 200 "$(req POST /api/rbac/roles/itest/permissions/remove -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' -d '{"permission_name":"soulauth:itest.read"}')" "撤销权限"
eq 0 "$(sql_count "SELECT count() FROM role_permission WHERE role_id IN (SELECT VALUE id FROM role WHERE name='itest') GROUP ALL")" \
    "撤销确实生效（不是只返回成功）"

group "5. OIDC 客户端与生命周期上限"

mk_client() {
    req POST /api/oidc/clients -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
        -d "{\"client_name\":\"$1\",\"client_type\":\"public\",
             \"redirect_uris\":[\"http://localhost:9000/cb\"],
             \"allowed_scopes\":[\"openid\"],
             \"allowed_grant_types\":[\"authorization_code\",\"refresh_token\"],
             \"allowed_response_types\":[\"code\"],\"require_pkce\":true
             ${2:+,\"id_token_lifetime\":$2}}" > /dev/null
}

mk_client clamp_hi 3600; eq 300 "$(jget id_token_lifetime)" "id_token_lifetime 3600 被夹到 300"
mk_client clamp_lo 60;   eq 60  "$(jget id_token_lifetime)" "id_token_lifetime 60 保持不变"
mk_client clamp_z  0;    eq 300 "$(jget id_token_lifetime)" "id_token_lifetime 0 回落到 300"

eq 404 "$(req GET /api/oidc/clients/no-such-client -H "Authorization: Bearer $ADMIN_TOKEN")" "不存在的客户端 404"
eq 404 "$(req DELETE /api/oidc/clients/no-such-client -H "Authorization: Bearer $ADMIN_TOKEN")" "禁用不存在的客户端 404（非 204）"
eq 404 "$(req POST /api/oidc/clients/no-such-client/regenerate-secret -H "Authorization: Bearer $ADMIN_TOKEN")" \
    "为不存在的客户端轮换密钥 404（非 200 + 假密钥）"

group "6. OIDC 授权码流程与 sid"

mk_client flow; CLIENT_ID="$(jget client_id)"
VERIFIER='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
CHALLENGE="$(python3 -c "
import hashlib,base64
print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")"

# 浏览器会话 cookie，authorize 靠它识别登录态
curl -sS --max-time 20 -c "$WORK/cookies" -o /dev/null \
    -X POST "${APP}/api/auth/login" -H 'Content-Type: application/json' \
    -d '{"email":"admin@test.local","password":"CorrectHorse42!"}' 2>/dev/null
EXPECT_SID="$(python3 -c "
import base64,json
tok=[l.split()[-1] for l in open('$WORK/cookies') if 'soulauth_session' in l][0]
p=tok.split('.')[1]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p))['sid'])" 2>/dev/null)"

AUTHZ="${APP}/api/oidc/authorize?client_id=${CLIENT_ID}&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcb&scope=openid&state=st"
LOC="$(curl -sS --max-time 20 -b "$WORK/cookies" -o /dev/null -D - \
    "${AUTHZ}&code_challenge=${CHALLENGE}&code_challenge_method=S256" 2>/dev/null | grep -i '^location:' | tr -d '\r')"
CODE="$(printf '%s' "$LOC" | sed -n 's/.*code=\([^&]*\).*/\1/p')"
[ -n "$CODE" ] && ok "S256 授权请求签发授权码" || bad "S256 授权请求签发授权码" "$LOC"

# PKCE 降级必须在下发阶段就被拒
LOC_PLAIN="$(curl -sS --max-time 20 -b "$WORK/cookies" -o /dev/null -D - \
    "${AUTHZ}&code_challenge=${VERIFIER}&code_challenge_method=plain" 2>/dev/null | grep -i '^location:' | tr -d '\r')"
has 'error=invalid_request' "$LOC_PLAIN" "PKCE plain 被拒绝"
LOC_NOM="$(curl -sS --max-time 20 -b "$WORK/cookies" -o /dev/null -D - \
    "${AUTHZ}&code_challenge=${CHALLENGE}" 2>/dev/null | grep -i '^location:' | tr -d '\r')"
has 'error=invalid_request' "$LOC_NOM" "缺 code_challenge_method 被拒绝"

exchange() {
    req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode 'grant_type=authorization_code' \
        --data-urlencode "code=$1" \
        --data-urlencode 'redirect_uri=http://localhost:9000/cb' \
        --data-urlencode "client_id=$CLIENT_ID" \
        --data-urlencode "code_verifier=$2"
}

eq 200 "$(exchange "$CODE" "$VERIFIER")" "授权码兑换成功"
ID_TOKEN="$(jget id_token)"; REFRESH="$(jget refresh_token)"

claim() {
    python3 -c "
import base64,json
p='$1'.split('.')[1]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p)).get('$2',''))" 2>/dev/null
}
eq "$EXPECT_SID" "$(claim "$ID_TOKEN" sid)" "ID Token 的 sid 等于认证会话主键"
eq 300 "$(( $(claim "$ID_TOKEN" exp) - $(claim "$ID_TOKEN" iat) ))" "ID Token 寿命为 300 秒"
has 'RS256' "$(python3 -c "
import base64,json
p='$ID_TOKEN'.split('.')[0]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p))['alg'])")" "ID Token 用 RS256 签名"

eq 400 "$(exchange "$CODE" "$VERIFIER")" "同一授权码不可复用"
has 'invalid_grant' "$(body)" "复用返回 invalid_grant"

# 刷新同样签发 ID Token，sid 必须继续传递
eq 200 "$(req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$REFRESH" \
    --data-urlencode "client_id=$CLIENT_ID")" "刷新令牌兑换成功"
eq "$EXPECT_SID" "$(claim "$(jget id_token)" sid)" "刷新后的 ID Token 保留同一 sid"

group "7. 认证会话缺失时拒签 ID Token（fail-closed）"

REFRESH2="$(jget refresh_token)"
sql "UPDATE oidc_refresh_token SET auth_session_ref = NONE WHERE client_id = '$CLIENT_ID'" > /dev/null
eq 400 "$(req POST /api/oidc/token -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=refresh_token' \
    --data-urlencode "refresh_token=$REFRESH2" \
    --data-urlencode "client_id=$CLIENT_ID")" "无会话引用时刷新被拒"
has 'Missing auth session reference' "$(body)" "拒绝原因明确"

group "8. OAuth 登录 CSRF 绑定"

restart_app   # 前面用掉了登录配额

HDRS="$(curl -sS --max-time 20 -o /dev/null -D - "${APP}/api/auth/login/google" 2>/dev/null)"
STATE="$(printf '%s' "$HDRS" | grep -io 'state=[^&[:space:]]*' | head -1 | cut -d= -f2 | tr -d '\r')"
NONCE="$(printf '%s' "$HDRS" | grep -io 'soulauth_oauth_state=[^;]*' | head -1 | cut -d= -f2 | tr -d '\r')"
[ -n "$NONCE" ] && ok "登录入口下发 state cookie" || bad "登录入口下发 state cookie"
has 'HttpOnly' "$HDRS" "state cookie 带 HttpOnly"

CB="/api/auth/callback/google?code=attacker-code&state=${STATE}"
eq 400 "$(req GET "$CB")" "有合法 state 但无 cookie —— 拒绝（这就是攻击场景）"
eq 400 "$(req GET "$CB" -H "Cookie: soulauth_oauth_state=00000000-0000-0000-0000-000000000000")" \
    "cookie nonce 不匹配 —— 拒绝"
eq 400 "$(req GET '/api/auth/callback/google?code=x')" "缺 state —— 拒绝"

# nonce 匹配时应越过 state 校验，止步于「拿假 code 找 Google 换令牌」
STATUS="$(req GET "$CB" -H "Cookie: soulauth_oauth_state=${NONCE}")"
has 'OAuth error' "$(body)" "nonce 匹配后越过 state 校验，止于上游兑换失败"

group "9. 账号锁定：并发失败登录不丢计数"

restart_app
sql "DELETE account_lockout" > /dev/null

PIDS=""
for _ in 1 2 3 4 5; do
    curl -sS --max-time 20 -o /dev/null -X POST "${APP}/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d '{"email":"admin@test.local","password":"WrongPassword999!"}' 2>/dev/null &
    PIDS="$PIDS $!"
done
for p in $PIDS; do wait "$p" 2>/dev/null; done   # 不能用裸 wait：会连服务进程一起等

eq 1 "$(sql_count "SELECT count() FROM account_lockout WHERE lockout_type='User' AND identifier='admin@test.local' GROUP ALL")" \
    "为该账号建立了锁定记录"
ATTEMPTS="$(sql "SELECT VALUE failed_attempts FROM account_lockout WHERE identifier='admin@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else 0)")"
eq 5 "$ATTEMPTS" "5 次并发失败全部计入（读-改-写会丢计数）"
STATUS_L="$(sql "SELECT VALUE status FROM account_lockout WHERE identifier='admin@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else '')")"
eq Locked "$STATUS_L" "达到阈值后置为 Locked"

group "10. 限流按路由模板计数"

restart_app

CODES=""
for i in 1 2 3 4 5 6; do
    CODES="$CODES $(req GET "/api/auth/verify-email/token-$i-$RANDOM")"
done
BLOCKED="$(printf '%s' "$CODES" | tr ' ' '\n' | grep -c 429)"
[ "$BLOCKED" -ge 1 ] &&
    ok "带路径参数的端点会被限流（每次 token 不同，共拦下 ${BLOCKED} 次）" ||
    bad "带路径参数的端点会被限流" "6 次请求无一被拦：$CODES"

group "11. 邮件投递：注册验证信"

# 这条链此前从未被验证过 —— 没有 SMTP 就只能标「无法实测」。
# 这里起一个零依赖的收信端（tests/smtp_sink.py），把整条
# 发信 → 取链接 → 验证 → 登录 走通。
#
# 信箱只增不清：断言用「收信数量的增量」，这样跑完还能用 KEEP_WORK=1
# 回看全部信件。清空信箱等于把证据自己抹掉。
MAILBOX="$WORK/mailbox.txt"
python3 "$ROOT/tests/smtp_sink.py" "$SINK_PORT" "$MAILBOX" > "$WORK/sink.log" 2>&1 &
SINK_PID=$!
disown "$SINK_PID" 2>/dev/null
sleep 1

VERIFY_EMAIL=true restart_app     # 开启邮箱验证后注册才会发信

BEFORE="$(mail_count)"
req POST /api/auth/register -H 'Content-Type: application/json' \
    -d '{"email":"mail@test.local","password":"CorrectHorse42!","username":"mailtest"}' > /dev/null
sleep 2                            # 发信走 spawn_blocking，给它落地的时间

eq "$((BEFORE + 1))" "$(mail_count)" "注册后确实发出了一封信"
eq 'Verify your email address' "$(mail_header Subject)" "主题为邮箱验证"
eq 'mail@test.local' "$(mail_header To)" "收件人正确"

VBODY="$(mail_body)"
case "$VBODY" in
    *CorrectHorse42*)                   bad "邮件不含用户密码" "正文里出现了明文密码" ;;
    *0123456789abcdef0123456789abcdef*) bad "邮件不含 JWT_SECRET" "正文里出现了签名密钥" ;;
    *)                                  ok "邮件不含密码与签名密钥" ;;
esac

VTOKEN="$(printf '%s' "$VBODY" | grep -oE 'token=[A-Za-z0-9-]+' | head -1 | cut -d= -f2)"
[ -n "$VTOKEN" ] && ok "验证链接里带 token" || bad "验证链接里带 token" "$VBODY"

DBTOKEN="$(sql "SELECT VALUE verification_token FROM user WHERE email='mail@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r and r[0] else '')")"
eq "$DBTOKEN" "$VTOKEN" "邮件里的 token 与库中一致（能对上才说明链接可用）"

eq 401 "$(req GET /api/auth/verify-email/deadbeef-not-a-real-token)" "伪造的验证 token 被拒"
eq 200 "$(req GET "/api/auth/verify-email/${VTOKEN}")" "真实 token 完成验证"

VERIFIED="$(sql "SELECT VALUE verified FROM user WHERE email='mail@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(str(r[0]).lower() if r else 'none')")"
eq true "$VERIFIED" "验证状态确实落库"

group "12. 邮件投递：密码重置信"

# 第 9 组是故意把 127.0.0.1 打到 IP 锁定的。锁定记录在库里，重启服务不会清，
# 而被锁时登录返回 429 —— 不清掉的话，本组的登录断言全成假阳性。
sql "DELETE account_lockout" > /dev/null
restart_app                          # 重置端点限流 3 次/15 分钟

BEFORE="$(mail_count)"
req POST /api/auth/request-password-reset -H 'Content-Type: application/json' \
    -d '{"email":"mail@test.local"}' > /dev/null
sleep 2
eq "$((BEFORE + 1))" "$(mail_count)" "申请重置后发出一封信"
eq 'Reset your password' "$(mail_header Subject)" "主题为密码重置"

# 重置链接是 {app_url}/reset-password/{token} 的路径形式，与验证信的 ?token= 不同
RBODY="$(mail_body)"
RTOKEN="$(printf '%s' "$RBODY" | grep -oE 'reset-password/[A-Za-z0-9-]+' | head -1 | cut -d/ -f2)"
[ -n "$RTOKEN" ] && ok "重置链接里带 token" || bad "重置链接里带 token" "$RBODY"

# 未注册邮箱不得发信，也不得因此暴露账号是否存在
BEFORE="$(mail_count)"
eq 200 "$(req POST /api/auth/request-password-reset -H 'Content-Type: application/json' \
    -d '{"email":"nobody-here@test.local"}')" "未注册邮箱同样返回 200（防枚举）"
sleep 1
eq "$BEFORE" "$(mail_count)" "未注册邮箱不发信"

eq 200 "$(req POST /api/auth/reset-password -H 'Content-Type: application/json' \
    -d "{\"token\":\"${RTOKEN}\",\"new_password\":\"BrandNewHorse43!\"}")" "用邮件里的 token 重置密码"
eq 401 "$(req POST /api/auth/reset-password -H 'Content-Type: application/json' \
    -d "{\"token\":\"${RTOKEN}\",\"new_password\":\"AnotherHorse44!\"}")" "同一 token 不可复用"

restart_app                          # 登录限流
eq 200 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"mail@test.local","password":"BrandNewHorse43!"}')" "可用新密码登录"
eq 401 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"mail@test.local","password":"CorrectHorse42!"}')" "旧密码已失效"

kill -9 "$SINK_PID" 2>/dev/null; SINK_PID=""

group "13. OAuth 回调：换到令牌之后的整段"

# 这一段此前完全没有覆盖：第 8 组只验到「拿假 code 去换令牌然后失败」，
# 再往后 —— 取用户信息、按邮箱验证状态放行、建号还是关联既有账号 ——
# 因为端点写死在代码里而无从下手。现在指向本地替身走完整条链。
python3 "$ROOT/tests/mock_oauth.py" "$OAUTH_PORT" > "$WORK/mock_oauth.log" 2>&1 &
MOCK_PID=$!
disown "$MOCK_PID" 2>/dev/null
sleep 1

sql "DELETE account_lockout" > /dev/null
OAUTH_BASE="http://127.0.0.1:${OAUTH_PORT}" restart_app

# 走一趟登录入口拿到配对的 state 与 cookie nonce（机制已在第 8 组验过）
oauth_callback() {   # $1=provider  $2=code  → 打印状态码
    local hdrs state nonce
    hdrs="$(curl -sS --max-time 20 -o /dev/null -D - "${APP}/api/auth/login/$1" 2>/dev/null)"
    state="$(printf '%s' "$hdrs" | grep -io 'state=[^&[:space:]]*' | head -1 | cut -d= -f2 | tr -d '\r')"
    nonce="$(printf '%s' "$hdrs" | grep -io 'soulauth_oauth_state=[^;]*' | head -1 | cut -d= -f2 | tr -d '\r')"
    req GET "/api/auth/callback/$1?code=$2&state=${state}" \
        -H "Cookie: soulauth_oauth_state=${nonce}" -D "$WORK/cb_headers"
}

# 回调成功走的是 303 See Other（axum `Redirect::to` 的既定状态码），不是 302。
redirected() {   # $1=描述
    local status="$2"
    if [ "$status" != 303 ]; then
        bad "$1" "期望 303 See Other，实际 $status"
        return
    fi
    # 重定向目标必须落在本服务的 app_url 之内。登录入口只接受本服务签发的
    # state，任意 return_to 进不来 —— 这条断言就是把该性质钉住，
    # 免得哪天入口放宽了、签名反而成了对攻击者 URL 的背书。
    local loc
    loc="$(grep -i '^location:' "$WORK/cb_headers" | head -1 | cut -d' ' -f2- | tr -d '\r')"
    case "$loc" in
        "$APP"/*) ok "$1（→ ${loc#$APP})" ;;
        *)        bad "$1" "重定向到了本服务之外：$loc" ;;
    esac
}

user_count() { sql_count "SELECT count() FROM user WHERE email='$1' GROUP ALL"; }
link_count() {
    sql_count "SELECT count() FROM identity_provider WHERE provider='$1' AND provider_user_id='$2' GROUP ALL"
}

# —— Google：新用户 ——
redirected "Google 回调成功后重定向" "$(oauth_callback google google-ok)"
eq 1 "$(user_count oauth-new@test.local)" "为新的 Google 用户建了账号"
eq 1 "$(link_count google google-uid-1)" "建立了 identity_provider 关联"

# 同一账号再来一次：必须复用，不能又建一个
redirected "同一 Google 账号二次登录" "$(oauth_callback google google-ok)"
eq 1 "$(user_count oauth-new@test.local)" "二次登录不重复建号"
eq 1 "$(link_count google google-uid-1)" "二次登录不重复建关联"

# —— Google：邮箱未验证必须拒绝 ——
# 放行的话，任何人在 provider 侧填一个未验证的他人邮箱就能顶号
eq 403 "$(oauth_callback google google-unverified)" "Google 邮箱未验证 → 拒绝"
eq 0 "$(user_count oauth-unverified@test.local)" "被拒的登录不留下账号"
eq 0 "$(link_count google google-uid-2)" "被拒的登录不留下关联"

# —— Google：邮箱撞上既有本地账号 → 关联，不新建 ——
BEFORE_ADMIN="$(user_count admin@test.local)"
redirected "邮箱已存在的 Google 登录成功" "$(oauth_callback google google-existing)"
eq "$BEFORE_ADMIN" "$(user_count admin@test.local)" "关联到既有账号而非新建重复账号"
eq 1 "$(link_count google google-uid-3)" "为既有账号补上了 Google 关联"

# —— GitHub：主邮箱取自 /user/emails ——
redirected "GitHub 回调成功后重定向" "$(oauth_callback github github-ok)"
eq 1 "$(user_count oauth-gh@test.local)" "取的是 primary+verified 那个邮箱"
eq 0 "$(user_count noreply@users.github.test)" "非 primary 的邮箱未被采用"
eq 1 "$(link_count github 4001)" "建立了 GitHub 关联"

# —— GitHub：无已验证主邮箱必须拒绝 ——
eq 403 "$(oauth_callback github github-unverified)" "GitHub 无已验证主邮箱 → 拒绝"
eq 0 "$(user_count gh-unverified@test.local)" "被拒的 GitHub 登录不留下账号"

# —— 无效授权码：上游 400，本服务不得当成成功 ——
STATUS="$(oauth_callback google definitely-not-a-code)"
[ "$STATUS" != 303 ] && ok "上游拒绝授权码时本服务不放行（${STATUS}）" ||
    bad "上游拒绝授权码时本服务不放行" "竟然签发了会话并重定向"

kill -9 "$MOCK_PID" 2>/dev/null; MOCK_PID=""

group "14. 运行期无 panic"


PANICS="$(grep -c 'panicked' "$WORK/app.log" 2>/dev/null)"; PANICS="${PANICS:-0}"
eq 0 "$PANICS" "服务日志中无 panic"

# ═══════════════════════════════ 汇总 ═══════════════════════════════

printf '\n%s\n' "────────────────────────────────"
if [ "$FAIL" -eq 0 ]; then
    printf '%s  通过 %d 项\n' "$(c_grn 全部通过)" "$PASS"
    exit 0
else
    printf '%s  通过 %d 项，失败 %s 项\n' "$(c_red 存在失败)" "$PASS" "$(c_red "$FAIL")"
    printf '%s\n' "$(c_dim "用 KEEP_WORK=1 重跑可保留服务日志与信箱现场")"
    exit 1
fi
