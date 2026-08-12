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
readonly APP2_PORT="${APP2_PORT:-8181}"   # 第二副本，用于验限流跨副本合账
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
APP2_PID=""

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
if not isinstance(b, dict):
    print(''); sys.exit()
v = b.get('$1')
# 布尔/数字要按 JSON 形态打印。直接 print 会得到 Python 的 True/False，
# 与接口返回的 true/false 对不上，断言就成了假失败。
print('' if v is None else v if isinstance(v, str) else json.dumps(v))" 2>/dev/null
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
    [ -n "$APP2_PID" ] && kill -9 "$APP2_PID" 2>/dev/null
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
    # 限流现在有两层：进程内的随重启清空，跨副本的存在库里 **不会**随重启清空
    # —— 这正是它要的性质（重启副本不能当解封手段）。测试里 restart_app 的用途
    # 是「给我一份干净的配额」，所以两层都得清，否则前面组用掉的配额会一路
    # 累到后面，表现为大面积 429。
    #
    # 第 20 组验跨副本合账时中途没有 restart_app，不受这里影响。
    sql "DELETE rate_limit" > /dev/null 2>&1
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
for p in "$SURREAL_PORT" "$APP_PORT" "$SINK_PORT" "$OAUTH_PORT" "$APP2_PORT"; do
    if ss -ltn 2>/dev/null | grep -q ":${p} "; then
        echo "端口 ${p} 已被占用；可用 SURREAL_PORT / APP_PORT / SINK_PORT / OAUTH_PORT / APP2_PORT 覆盖"; exit 2
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

# —— GitHub：登录入口与回调 ——
# 入口要下发 state cookie 并重定向到（被覆盖后的）授权端点
GH_HDRS="$(curl -sS --max-time 20 -o /dev/null -D - "${APP}/api/auth/login/github" 2>/dev/null)"
has 'soulauth_oauth_state' "$GH_HDRS" "GitHub 登录入口下发 state cookie"
case "$GH_HDRS" in
    *"127.0.0.1:${OAUTH_PORT}/login/oauth/authorize"*)
        ok "GitHub 授权地址走的是被覆盖的端点（路径形状与真实 GitHub 一致）" ;;
    *)  bad "GitHub 授权地址走的是被覆盖的端点" "$(printf '%s' "$GH_HDRS" | grep -i '^location:')" ;;
esac

# —— GitHub：主邮箱取自 /user/emails ——
redirected "GitHub 回调成功后重定向" "$(oauth_callback github github-ok)"
eq 1 "$(user_count oauth-gh@test.local)" "取的是 primary+verified 那个邮箱"
eq 0 "$(user_count noreply@users.github.test)" "非 primary 的邮箱未被采用"
eq 1 "$(link_count github 4001)" "建立了 GitHub 关联"

# —— GitHub：无已验证主邮箱必须拒绝 ——
# 回调路径：/api/auth/callback/github（由 oauth_callback 拼出）
eq 403 "$(oauth_callback github github-unverified)" "GitHub 无已验证主邮箱 → 拒绝"
eq 0 "$(user_count gh-unverified@test.local)" "被拒的 GitHub 登录不留下账号"

# —— 无效授权码：上游 400，本服务不得当成成功 ——
STATUS="$(oauth_callback google definitely-not-a-code)"
[ "$STATUS" != 303 ] && ok "上游拒绝授权码时本服务不放行（${STATUS}）" ||
    bad "上游拒绝授权码时本服务不放行" "竟然签发了会话并重定向"

kill -9 "$MOCK_PID" 2>/dev/null; MOCK_PID=""

group "14. 登出与会话吊销"

# 「登出返回 200」什么也证明不了 —— 要证明的是**那个令牌真的不能再用了**。
# 这一段直接关系 OS 接入：OS 拿 sid 指向的会话做判断，注销做不干净就是安全洞。
restart_app
sql "DELETE account_lockout" > /dev/null

login_token() {   # $1=邮箱 $2=密码 → 打印 access_token（拿不到则空）
    req POST /api/auth/login -H 'Content-Type: application/json' \
        -d "{\"email\":\"$1\",\"password\":\"$2\"}" > /dev/null
    jget token
}

TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
[ -n "$TOK_A" ] && ok "登录拿到令牌" || bad "登录拿到令牌" "$(body)"
eq 200 "$(req GET /api/auth/me -H "Authorization: Bearer ${TOK_A}")" "令牌可用"
eq 200 "$(req GET /api/auth/sessions -H "Authorization: Bearer ${TOK_A}")" "可列出自己的会话"
eq 401 "$(req GET /api/auth/sessions)" "无令牌列会话 → 401"

eq 200 "$(req POST /api/auth/logout -H "Authorization: Bearer ${TOK_A}")" "登出返回成功"
eq 401 "$(req GET /api/auth/me -H "Authorization: Bearer ${TOK_A}")" "登出后原令牌立即失效（不等缓存 TTL）"

# logout-all：签两个令牌，注销后两个都得死
TOK_B="$(login_token admin@test.local "CorrectHorse42!")"
TOK_C="$(login_token admin@test.local "CorrectHorse42!")"
[ -n "$TOK_B" ] && [ -n "$TOK_C" ] && [ "$TOK_B" != "$TOK_C" ] &&
    ok "两次登录得到两个不同令牌" || bad "两次登录得到两个不同令牌" "B=${TOK_B:0:12} C=${TOK_C:0:12}"

eq 200 "$(req POST /api/auth/logout-all -H "Authorization: Bearer ${TOK_B}")" "全端登出返回成功"
eq 401 "$(req GET /api/auth/me -H "Authorization: Bearer ${TOK_B}")" "发起方令牌失效"
eq 401 "$(req GET /api/auth/me -H "Authorization: Bearer ${TOK_C}")" "另一条会话的令牌同样失效"

group "15. MFA 全生命周期（真实 TOTP）"

# 之前只有单测级的 last_totp_step 水位线，整条链路没端到端跑过。
# 这里用 RFC 6238 算真码（tests/totp.py，已用标准向量自校）。
restart_app

MFA_MAIL="mfa@test.local"
MFA_PW="CorrectHorse42!"
req POST /api/auth/register -H 'Content-Type: application/json' \
    -d "{\"email\":\"${MFA_MAIL}\",\"password\":\"${MFA_PW}\",\"username\":\"mfauser\"}" > /dev/null
TOK="$(login_token "$MFA_MAIL" "$MFA_PW")"
[ -n "$TOK" ] && ok "MFA 测试账号登录成功" || bad "MFA 测试账号登录成功" "$(body)"

req GET /api/auth/mfa/status -H "Authorization: Bearer ${TOK}" > /dev/null
eq false "$(jget enabled)" "初始未开启 MFA"

eq 200 "$(req POST /api/auth/mfa/setup -H "Authorization: Bearer ${TOK}")" "setup 返回成功"
SECRET="$(jget secret)"
BACKUP="$(python3 -c "
import json;d=json.load(open('$WORK/body'));c=d.get('backup_codes') or [];print(c[0] if c else '')" 2>/dev/null)"
[ -n "$SECRET" ] && ok "setup 下发了 TOTP 密钥" || bad "setup 下发了 TOTP 密钥" "$(body)"
[ -n "$BACKUP" ] && ok "setup 下发了备用码" || bad "setup 下发了备用码" "$(body)"

# 还没 enable 时不算开启 —— setup 只是备好，别把「拿到密钥」当成「已启用」
req GET /api/auth/mfa/status -H "Authorization: Bearer ${TOK}" > /dev/null
eq false "$(jget enabled)" "仅 setup 尚未启用"

eq 400 "$(req POST /api/auth/mfa/enable -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' -d '{"totp_code":"000000"}')" "错误验证码不能启用"

# 用**上一个**时间窗的码启用，把水位线压在 S-1；
# 这样下面用当前窗口的码登录时不会被自己的水位线挡住，且全程无需 sleep。
# 避开时间窗边界。守卫必须紧挨着取码：中间若还夹着几个 HTTP 往返而恰好跨了窗口，
# CODE_PREV 就落到当前窗口的 2 个之外，会被 ±1 的容差挡掉，测试变成偶发失败。
INTO="$(python3 "$ROOT/tests/totp.py" --seconds-into-step)"
awk -v v="$INTO" 'BEGIN{exit !(v > 22)}' && sleep 9

CODE_PREV="$(python3 "$ROOT/tests/totp.py" "$SECRET" -1)"
eq 200 "$(req POST /api/auth/mfa/enable -H "Authorization: Bearer ${TOK}" \
    -H 'Content-Type: application/json' -d "{\"totp_code\":\"${CODE_PREV}\"}")" "真实验证码启用 MFA"

req GET /api/auth/mfa/status -H "Authorization: Bearer ${TOK}" > /dev/null
eq true "$(jget enabled)" "状态显示已启用"

# 开启后登录必须停在 MFA 挑战，而不是直接发会话令牌
req POST /api/auth/login -H 'Content-Type: application/json' \
    -d "{\"email\":\"${MFA_MAIL}\",\"password\":\"${MFA_PW}\"}" > /dev/null
eq true "$(jget mfa_required)" "开启后登录要求补 MFA"
TEMP="$(jget temp_token)"
[ -n "$TEMP" ] && ok "下发了挑战令牌" || bad "下发了挑战令牌" "$(body)"
[ -z "$(jget token)" ] && ok "挑战阶段不下发会话令牌" || bad "挑战阶段不下发会话令牌" "竟然直接给了 token"

eq 401 "$(req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP}\",\"totp_code\":\"000000\"}")" "错误验证码不能过 MFA"

CODE_NOW="$(python3 "$ROOT/tests/totp.py" "$SECRET" 0)"
req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP}\",\"totp_code\":\"${CODE_NOW}\"}" > /dev/null
[ -n "$(jget token)" ] && ok "真实验证码完成 MFA 登录" || bad "真实验证码完成 MFA 登录" "$(body)"

# 重放：同一个码不得再用一次（last_totp_step 水位线）
req POST /api/auth/login -H 'Content-Type: application/json' \
    -d "{\"email\":\"${MFA_MAIL}\",\"password\":\"${MFA_PW}\"}" > /dev/null
TEMP2="$(jget temp_token)"
eq 401 "$(req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP2}\",\"totp_code\":\"${CODE_NOW}\"}")" "同一验证码不可重放"
eq 401 "$(req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP2}\",\"totp_code\":\"${CODE_PREV}\"}")" "更早窗口的码同样被水位线挡住"

# 备用码：能用一次，且只能用一次
req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP2}\",\"backup_code\":\"${BACKUP}\"}" > /dev/null
TOK_MFA="$(jget token)"
[ -n "$TOK_MFA" ] && ok "备用码可完成登录" || bad "备用码可完成登录" "$(body)"

restart_app   # login / login-verify 共用登录限流，前面已用满，不重启就测成 429
req POST /api/auth/login -H 'Content-Type: application/json' \
    -d "{\"email\":\"${MFA_MAIL}\",\"password\":\"${MFA_PW}\"}" > /dev/null
TEMP3="$(jget temp_token)"
eq 401 "$(req POST /api/auth/mfa/login-verify -H 'Content-Type: application/json' \
    -d "{\"temp_token\":\"${TEMP3}\",\"backup_code\":\"${BACKUP}\"}")" "同一备用码不可复用"

CODE_OFF="$(python3 "$ROOT/tests/totp.py" "$SECRET" 1)"
eq 200 "$(req POST /api/auth/mfa/disable -H "Authorization: Bearer ${TOK_MFA}" \
    -H 'Content-Type: application/json' -d "{\"totp_code\":\"${CODE_OFF}\"}")" "可用验证码关闭 MFA"
req GET /api/auth/mfa/status -H "Authorization: Bearer ${TOK_MFA}" > /dev/null
eq false "$(jget enabled)" "关闭后状态归位"

group "16. SSO 会话"

# 这个模块 11 个端点此前零覆盖，而它正是 OIDC 单点登录的会话骨架 ——
# ID Token 里的 sid 指向的就是它。
restart_app

TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
TOK_P="$(login_token plain@test.local "CorrectHorse42!")"

# 关键授权性质：请求体里的 user_id 会被强制改写成调用者，
# 否则任何登录用户都能给别人凭空造会话。
ADMIN_UID="$(user_id_of admin@test.local)"
req POST /api/sso/sessions -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' \
    -d "{\"user_id\":\"${ADMIN_UID}\",\"client_id\":\"c1\",\"ip_address\":\"127.0.0.1\",\"user_agent\":\"itest\"}" > /dev/null
SID_P="$(jget session_id)"
OWNER="$(jget user_id)"
[ -n "$SID_P" ] && ok "创建 SSO 会话成功" || bad "创建 SSO 会话成功" "$(body)"
[ "$OWNER" != "$ADMIN_UID" ] && ok "请求体里的 user_id 被忽略（不能替他人造会话）" ||
    bad "请求体里的 user_id 被忽略" "会话归属被指定成了 ${ADMIN_UID}"

eq 200 "$(req GET "/api/sso/sessions/${SID_P}" -H "Authorization: Bearer ${TOK_P}")" "本人可读自己的会话"
eq 404 "$(req GET "/api/sso/sessions/no-such-session-id" -H "Authorization: Bearer ${TOK_P}")" \
    "不存在的会话 404（而非把库错误伪装成 404 之外的码）"

# 跨用户读取要 USERS_READ：admin 有，普通用户没有
req POST /api/sso/sessions -H "Authorization: Bearer ${TOK_A}" \
    -H 'Content-Type: application/json' \
    -d '{"user_id":"x","client_id":"c1","ip_address":"127.0.0.1","user_agent":"itest"}' > /dev/null
SID_A="$(jget session_id)"
eq 200 "$(req GET "/api/sso/sessions/${SID_A}" -H "Authorization: Bearer ${TOK_A}")" "管理员可读自己的会话"
eq 403 "$(req GET "/api/sso/sessions/${SID_A}" -H "Authorization: Bearer ${TOK_P}")" \
    "无 users.read 的用户读不了别人的会话"

# 客户端会话的增删
eq 200 "$(req POST "/api/sso/sessions/${SID_P}/clients/webapp" -H "Authorization: Bearer ${TOK_P}")" "挂上客户端会话"
req GET "/api/sso/sessions/${SID_P}" -H "Authorization: Bearer ${TOK_P}" > /dev/null
has 'webapp' "$(body)" "会话详情里能看到该客户端"
eq 200 "$(req DELETE "/api/sso/sessions/${SID_P}/clients/webapp" -H "Authorization: Bearer ${TOK_P}")" "摘掉客户端会话"
req GET "/api/sso/sessions/${SID_P}" -H "Authorization: Bearer ${TOK_P}" > /dev/null
case "$(body)" in *webapp*) bad "摘除后详情里不再有该客户端" "$(body)" ;; *) ok "摘除后详情里不再有该客户端" ;; esac

# 续期：过期时间必须真的往后走
req GET "/api/sso/sessions/${SID_P}" -H "Authorization: Bearer ${TOK_P}" > /dev/null
EXP_BEFORE="$(jget expires_at)"
eq 200 "$(req POST "/api/sso/sessions/${SID_P}/extend" -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"extend_seconds":3600}')" "续期返回成功"
req GET "/api/sso/sessions/${SID_P}" -H "Authorization: Bearer ${TOK_P}" > /dev/null
EXP_AFTER="$(jget expires_at)"
[ -n "$EXP_AFTER" ] && [ "$EXP_AFTER" != "$EXP_BEFORE" ] &&
    ok "续期后过期时间确实变化（不是只返回成功）" ||
    bad "续期后过期时间确实变化" "前 ${EXP_BEFORE} 后 ${EXP_AFTER}"

# 统计与清理：SECURITY_READ 才能看
eq 200 "$(req GET /api/sso/sessions/stats -H "Authorization: Bearer ${TOK_A}")" "管理员可看全局会话统计"
eq 403 "$(req GET /api/sso/sessions/stats -H "Authorization: Bearer ${TOK_P}")" "无 security.read 看不了全局统计"
# 目标用户按 user_id 解析，没有 "me" 这种字面量；本人可看，他人需 users.read
PLAIN_UID="$(user_id_of plain@test.local)"
eq 200 "$(req GET "/api/sso/users/${PLAIN_UID}/sessions/stats" -H "Authorization: Bearer ${TOK_P}")" "可看自己的会话统计"
eq 403 "$(req GET "/api/sso/users/${ADMIN_UID}/sessions/stats" -H "Authorization: Bearer ${TOK_P}")" "看不了他人的会话统计"
eq 200 "$(req GET "/api/sso/users/${PLAIN_UID}/sessions" -H "Authorization: Bearer ${TOK_P}")" "可列出自己的全部会话"
eq 403 "$(req GET "/api/sso/users/${ADMIN_UID}/sessions" -H "Authorization: Bearer ${TOK_P}")" "列不了他人的会话"
eq 200 "$(req POST /api/sso/sessions/cleanup -H "Authorization: Bearer ${TOK_A}")" "管理员可触发过期清理"
eq 403 "$(req POST /api/sso/sessions/cleanup -H "Authorization: Bearer ${TOK_P}")" "无 security.read 不能触发清理"

# 注销单个会话，之后应查不到
eq 204 "$(req DELETE "/api/sso/sessions/${SID_P}" -H "Authorization: Bearer ${TOK_P}")" "注销单个 SSO 会话（204 No Content）"
eq 404 "$(req GET "/api/sso/sessions/${SID_P}" -H "Authorization: Bearer ${TOK_P}")" "注销后查不到该会话"

# 批量注销：先另造一条，注销后自己的会话数应归零
req POST /api/sso/sessions -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' \
    -d '{"user_id":"x","client_id":"c2","ip_address":"127.0.0.1","user_agent":"itest"}' > /dev/null
eq 200 "$(req DELETE "/api/sso/users/${PLAIN_UID}/sessions" -H "Authorization: Bearer ${TOK_P}")" "可注销自己的全部会话"
req GET "/api/sso/users/${PLAIN_UID}/sessions" -H "Authorization: Bearer ${TOK_P}" > /dev/null
ACTIVE="$(python3 -c "
import json
d = json.load(open('$WORK/body'))
rows = d.get('data', d) if isinstance(d, dict) else d
print(sum(1 for r in rows if r.get('is_active')) if isinstance(rows, list) else 'NOT_A_LIST')" 2>/dev/null)"
eq 0 "$ACTIVE" "全部注销后无活跃会话"

group "17. 用户资料与偏好"

restart_app
sql "DELETE account_lockout" > /dev/null

TOK_P="$(login_token plain@test.local "CorrectHorse42!")"
TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
PLAIN_UID="$(user_id_of plain@test.local)"
ADMIN_UID="$(user_id_of admin@test.local)"

# 已知缺陷：资料/偏好在 POST 建立之前读取返回 404 而不是空对象。
# 这里把现状钉住 —— 哪天改成返回空对象，这条会红，提醒同步前端与文档。
eq 404 "$(req GET /api/users/profile -H "Authorization: Bearer ${TOK_P}")" \
    "尚未建立时读资料 → 404（现状，非空对象）"

eq 200 "$(req POST /api/users/profile -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"display_name":"Plain User","bio":"hello"}')" "建立资料"
req GET /api/users/profile -H "Authorization: Bearer ${TOK_P}" > /dev/null
has 'Plain User' "$(body)" "读回自己的资料"

eq 200 "$(req PUT /api/users/profile -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"display_name":"Renamed","bio":"updated"}')" "更新资料"
req GET /api/users/profile -H "Authorization: Bearer ${TOK_P}" > /dev/null
has 'Renamed' "$(body)" "更新确实落库（不是只返回成功）"

eq 200 "$(req POST /api/users/preferences -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"language":"zh-CN","timezone":"Asia/Shanghai"}')" "建立偏好"
eq 200 "$(req PUT /api/users/preferences -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"language":"en-US","timezone":"UTC"}')" "更新偏好"
req GET /api/users/preferences -H "Authorization: Bearer ${TOK_P}" > /dev/null
has 'en-US' "$(body)" "偏好更新落库"

eq 200 "$(req GET /api/users/activity-log -H "Authorization: Bearer ${TOK_P}")" "可读自己的活动日志"
eq 401 "$(req GET /api/users/profile)" "无令牌读资料 → 401"

# 跨用户读取：本人之外一律要权限
eq 200 "$(req GET "/api/users/users/${PLAIN_UID}/profile" -H "Authorization: Bearer ${TOK_A}")" \
    "管理员可读他人资料（users.read）"
eq 403 "$(req GET "/api/users/users/${ADMIN_UID}/profile" -H "Authorization: Bearer ${TOK_P}")" \
    "无 users.read 读不了他人资料"
eq 403 "$(req GET "/api/users/users/${ADMIN_UID}/preferences" -H "Authorization: Bearer ${TOK_P}")" \
    "无 users.read 读不了他人偏好"
eq 403 "$(req GET "/api/users/users/${ADMIN_UID}/activity-log" -H "Authorization: Bearer ${TOK_P}")" \
    "无 audit.read 读不了他人活动日志"
eq 200 "$(req GET "/api/users/users/${PLAIN_UID}" -H "Authorization: Bearer ${TOK_A}")" "管理员可按 id 读用户"
eq 403 "$(req GET "/api/users/users/${ADMIN_UID}" -H "Authorization: Bearer ${TOK_P}")" "普通用户按 id 读不了他人"

group "18. 账号状态与会员等级：越权与即时失效"

restart_app

TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
VICTIM_TOKEN="$(signup victim@test.local victimtest)"
VICTIM_UID="$(user_id_of victim@test.local)"
[ -n "$VICTIM_TOKEN" ] && ok "受害账号建立并登录" || bad "受害账号建立并登录" "$(body)"

# 越权：普通用户不得改任何人的状态，包括自己
eq 403 "$(req PUT "/api/users/users/${VICTIM_UID}/status" -H "Authorization: Bearer ${VICTIM_TOKEN}" \
    -H 'Content-Type: application/json' -d '{"status":"Active","reason":"self"}')" \
    "无 users.write 改不了自己的状态"
eq 403 "$(req PUT "/api/users/users/${VICTIM_UID}/membership" -H "Authorization: Bearer ${VICTIM_TOKEN}" \
    -H 'Content-Type: application/json' -d '{"membership_level":"PRO"}')" \
    "无 users.write 不能自封会员等级"

# 会员等级由管理员改，且要真的落库
eq 200 "$(req PUT "/api/users/users/${VICTIM_UID}/membership" -H "Authorization: Bearer ${TOK_A}" \
    -H 'Content-Type: application/json' -d '{"membership_level":"PRO"}')" "管理员可改会员等级"
LEVEL="$(sql "SELECT VALUE membership_level FROM user WHERE email='victim@test.local'" |
    python3 -c "import json,sys;r=json.load(sys.stdin);print(r[0] if r else '')")"
eq PRO "$LEVEL" "会员等级确实落库"

# 停用之后，**已经签发的令牌必须立刻失效**。
# 这是本组的核心：只清缓存而不在校验时看状态，被停用的人还能继续用到令牌自然过期。
eq 200 "$(req GET /api/auth/me -H "Authorization: Bearer ${VICTIM_TOKEN}")" "停用前令牌可用"
eq 200 "$(req PUT "/api/users/users/${VICTIM_UID}/status" -H "Authorization: Bearer ${TOK_A}" \
    -H 'Content-Type: application/json' -d '{"status":"Suspended","reason":"itest"}')" "管理员停用该账号"
# 停用后的判定用显式 if：`[ A ] || [ B ] && ok || bad` 在 shell 里是
# 左结合的等优先级串联，读起来像三元表达式，实际语义靠碰巧。
STATUS="$(req GET /api/auth/me -H "Authorization: Bearer ${VICTIM_TOKEN}")"
if [ "$STATUS" = 401 ] || [ "$STATUS" = 403 ]; then
    ok "停用后原令牌立即失效（${STATUS}）"
else
    bad "停用后原令牌立即失效" "竟然仍可用：${STATUS}"
fi

# 被停用的账号也不能重新登录
eq 403 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"victim@test.local","password":"CorrectHorse42!"}')" "被停用账号无法重新登录"

# 库里被写进未知状态时必须按不可用处理（fail-closed 白名单）
sql "UPDATE user SET account_status = 'SomeFutureStatus' WHERE email = 'victim@test.local'" > /dev/null
restart_app
eq 403 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"victim@test.local","password":"CorrectHorse42!"}')" \
    "未知账号状态按不可用处理（未列白名单即拒）"

group "19. RBAC 用户侧授权与权限查询"

restart_app

TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
TOK_P="$(login_token plain@test.local "CorrectHorse42!")"
PLAIN_UID="$(user_id_of plain@test.local)"

# 自查端点只看自己，不接受目标用户参数
req GET "/api/rbac/check/permission/soulauth:users.read" -H "Authorization: Bearer ${TOK_A}" > /dev/null
eq true "$(jget has_permission)" "管理员自查 users.read → 有"
req GET "/api/rbac/check/permission/soulauth:users.read" -H "Authorization: Bearer ${TOK_P}" > /dev/null
eq false "$(jget has_permission)" "普通用户自查 users.read → 无"
req GET "/api/rbac/check/role/admin" -H "Authorization: Bearer ${TOK_P}" > /dev/null
eq false "$(jget has_role)" "普通用户自查 admin 角色 → 无"
eq 401 "$(req GET "/api/rbac/check/role/admin")" "自查端点仍需登录"

eq 200 "$(req GET "/api/rbac/permissions/soulauth:users.read" -H "Authorization: Bearer ${TOK_A}")" "可按名读取权限详情"
eq 403 "$(req GET "/api/rbac/permissions/soulauth:users.read" -H "Authorization: Bearer ${TOK_P}")" \
    "无 permissions.read 读不了权限详情"

# 越权：普通用户不得给自己授角色
eq 403 "$(req POST "/api/rbac/users/${PLAIN_UID}/roles/assign" -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"role_name":"admin"}')" \
    "无 roles.write 不能给自己授 admin（提权面）"
eq 0 "$(sql_count "SELECT count() FROM user_role WHERE user_id = type::record('user','${PLAIN_UID}') AND role_id = role:admin GROUP ALL")" \
    "越权尝试没有留下任何授权记录"

# 管理员授角色，且要落库、可查、可撤
eq 200 "$(req POST "/api/rbac/users/${PLAIN_UID}/roles/assign" -H "Authorization: Bearer ${TOK_A}" \
    -H 'Content-Type: application/json' -d '{"role_name":"user"}')" "管理员给用户授角色"
eq 1 "$(sql_count "SELECT count() FROM user_role WHERE user_id = type::record('user','${PLAIN_UID}') AND role_id = role:user GROUP ALL")" \
    "授权确实落库"
req GET "/api/rbac/users/${PLAIN_UID}/roles" -H "Authorization: Bearer ${TOK_A}" > /dev/null
has 'user' "$(body)" "角色列表里能查到"
eq 200 "$(req GET "/api/rbac/users/${PLAIN_UID}/permissions" -H "Authorization: Bearer ${TOK_A}")" "可查该用户的权限集合"
# 查自己的角色不需要额外权限（handler 里有 self 放行），查别人才要 users.read
eq 200 "$(req GET "/api/rbac/users/${PLAIN_UID}/roles" -H "Authorization: Bearer ${TOK_P}")" \
    "查自己的角色无需额外权限"
ADMIN_UID="$(user_id_of admin@test.local)"
eq 403 "$(req GET "/api/rbac/users/${ADMIN_UID}/roles" -H "Authorization: Bearer ${TOK_P}")" \
    "无 users.read 查不了他人角色"

eq 200 "$(req POST "/api/rbac/users/${PLAIN_UID}/roles/remove" -H "Authorization: Bearer ${TOK_A}" \
    -H 'Content-Type: application/json' -d '{"role_name":"user"}')" "管理员撤销角色"
eq 0 "$(sql_count "SELECT count() FROM user_role WHERE user_id = type::record('user','${PLAIN_UID}') AND role_id = role:user GROUP ALL")" \
    "撤销确实生效（不是只返回成功）"

group "20. 限流跨副本合账"

# 这条性质**只能用两个真实进程验**：单进程里怎么测都测不出「各副本各算各的」。
# 起第二个副本，与第一个共用同一个数据库，配置完全一致 —— 就是生产上
# 挂在负载均衡后面的样子。
restart_app
sql "DELETE account_lockout" > /dev/null
sql "DELETE rate_limit" > /dev/null

APP2="http://127.0.0.1:${APP2_PORT}"
(
    cd "$ROOT"
    DATABASE_URL="127.0.0.1:${SURREAL_PORT}" \
    DATABASE_USER=root DATABASE_PASS=root \
    DATABASE_NAMESPACE=auth DATABASE_NAME=main \
    JWT_SECRET=0123456789abcdef0123456789abcdef \
    GOOGLE_CLIENT_ID=dummy GOOGLE_CLIENT_SECRET=dummy \
    GITHUB_CLIENT_ID=dummy GITHUB_CLIENT_SECRET=dummy \
    OAUTH_REDIRECT_URL="${APP2}/api/auth/callback" \
    SMTP_HOST=127.0.0.1 SMTP_PORT="${SINK_PORT}" SMTP_FROM=noreply@example.com \
    SMTP_INSECURE=true APP_URL="$APP2" \
    BIND_ADDR="127.0.0.1:${APP2_PORT}" RUST_LOG=rust_auth=warn \
    exec ./target/debug/rust-auth
) > "$WORK/app2.log" 2>&1 &
APP2_PID=$!
disown "$APP2_PID" 2>/dev/null
for _ in $(seq 1 40); do
    curl -sS --max-time 2 -o /dev/null "${APP2}/api/oidc/jwks" 2>/dev/null && break
    sleep 0.5
done
curl -sS --max-time 2 -o /dev/null "${APP2}/api/oidc/jwks" 2>/dev/null &&
    ok "第二副本已就绪" || { bad "第二副本已就绪" "$(tail -5 "$WORK/app2.log")"; }

# 在副本 1 上把登录配额打满（5 次/5 分钟）
CODES1=""
for i in 1 2 3 4 5; do
    CODES1="$CODES1 $(req POST /api/auth/login -H 'Content-Type: application/json' \
        -d '{"email":"nobody@test.local","password":"WrongPassword999!"}')"
done
case "$CODES1" in *429*) bad "副本1 前 5 次不该被限流" "$CODES1" ;; *) ok "副本1 用满 5 次配额" ;; esac
eq 429 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"nobody@test.local","password":"WrongPassword999!"}')" "副本1 第 6 次被限流"

# 核心断言：换到副本 2 也必须被拦。
# 不共享的话副本 2 的计数是 0，会照常放行 —— 攻击者摊到 N 个副本上就有 N 倍配额。
CODE2="$(curl -sS --max-time 25 -o /dev/null -w '%{http_code}' \
    -X POST "${APP2}/api/auth/login" -H 'Content-Type: application/json' \
    -d '{"email":"nobody@test.local","password":"WrongPassword999!"}' 2>/dev/null)"
eq 429 "$CODE2" "换到第二副本同样被拦（配额跨副本合账）"

# 计数确实落在共享表里，而不是各存各的
SHARED_ROWS="$(sql_count "SELECT count() FROM rate_limit WHERE endpoint = '/api/auth/login' GROUP ALL")"
eq 1 "$SHARED_ROWS" "两个副本共用同一个计数桶（只有一条记录）"

# 一般 API 走进程内，不该在共享表里留记录 —— 否则等于给每个请求加一次库写
req GET /api/auth/me > /dev/null
eq 0 "$(sql_count "SELECT count() FROM rate_limit WHERE endpoint = '/api/auth/me' GROUP ALL")" \
    "默认规则的端点不写共享表（热路径不加数据库往返）"

kill -9 "$APP2_PID" 2>/dev/null; APP2_PID=""

group "21. 审计 / OIDC userinfo / 管理端剩余端点"

# 这批端点此前只手工 curl 验过（当时还从中揪出过 security-report 的 500），
# 一直没进自动化 = 没有回归保护。补上。
#
# 关键：**必须在有数据的情况下验**。空表上跑这些统计接口一律返回 200，
# 什么也证明不了 —— 上次那个 500 正是把表填上之后才暴露的。
restart_app
sql "DELETE account_lockout" > /dev/null

TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
TOK_P="$(login_token plain@test.local "CorrectHorse42!")"

# 造点审计数据：几次失败登录 + 几次成功请求
for _ in 1 2 3; do
    req POST /api/auth/login -H 'Content-Type: application/json' \
        -d '{"email":"admin@test.local","password":"WrongPassword999!"}' > /dev/null
done
sleep 1   # 审计是异步落库的，给它一点时间
ACT_ROWS="$(sql_count "SELECT count() FROM user_activity GROUP ALL")"
[ "${ACT_ROWS:-0}" -gt 0 ] && ok "审计表里确实有数据（${ACT_ROWS} 条），统计接口不是在空集上跑" ||
    bad "审计表里确实有数据" "仍是空表，后面的断言证明不了任何事"

restart_app   # 上面把登录配额用掉了
TOK_A="$(login_token admin@test.local "CorrectHorse42!")"
TOK_P="$(login_token plain@test.local "CorrectHorse42!")"

eq 200 "$(req GET /api/audit/dashboard -H "Authorization: Bearer ${TOK_A}")" "审计看板"
eq 200 "$(req GET /api/audit/activity-summary -H "Authorization: Bearer ${TOK_A}")" "活动摘要"
eq 200 "$(req GET /api/audit/security-report -H "Authorization: Bearer ${TOK_A}")" "安全报告（有数据时）"
eq 200 "$(req GET /api/audit/security-metrics -H "Authorization: Bearer ${TOK_A}")" "安全指标"
eq 200 "$(req GET /api/audit/system-health -H "Authorization: Bearer ${TOK_A}")" "系统健康"

eq 403 "$(req GET /api/audit/activity-summary -H "Authorization: Bearer ${TOK_P}")" "无 audit.read 看不了活动摘要"
eq 403 "$(req GET /api/audit/security-metrics -H "Authorization: Bearer ${TOK_P}")" "无 security.read 看不了安全指标"
eq 403 "$(req GET /api/audit/system-health -H "Authorization: Bearer ${TOK_P}")" "无 security.read 看不了系统健康"
eq 401 "$(req GET /api/audit/security-report)" "无令牌看不了安全报告"

# system-health 报的运行时长必须是真的（曾经写死过 3600）
req GET /api/audit/system-health -H "Authorization: Bearer ${TOK_A}" > /dev/null
case "$(body)" in *3600*) bad "运行时长不是写死的 3600" "$(body)" ;; *) ok "运行时长不是写死的 3600" ;; esac

eq 200 "$(req GET /api/ops/memberships/overview -H "Authorization: Bearer ${TOK_A}")" "会员总览"
eq 403 "$(req GET /api/ops/memberships/overview -H "Authorization: Bearer ${TOK_P}")" "无 users.read 看不了会员总览"

# OIDC userinfo：只认 OIDC 访问令牌，不认普通会话令牌
eq 401 "$(req GET /api/oidc/userinfo)" "userinfo 无令牌 → 401"
eq 401 "$(req GET /api/oidc/userinfo -H "Authorization: Bearer ${TOK_A}")" \
    "userinfo 不接受普通会话令牌（两套令牌不可混用）"
eq 401 "$(req GET /api/oidc/userinfo -H 'Authorization: Bearer not-a-real-token')" "userinfo 拒伪造令牌"

# OIDC 登出端点：无参数也应给出可用响应，不得 5xx
LOGOUT_CODE="$(req GET /api/oidc/logout)"
case "$LOGOUT_CODE" in 5*) bad "OIDC 登出端点不 5xx" "返回 $LOGOUT_CODE" ;; *) ok "OIDC 登出端点不 5xx（${LOGOUT_CODE}）" ;; esac

# 管理后台登录：普通用户即使密码对也不得放行
eq 200 "$(req POST /api/auth/admin/login -H 'Content-Type: application/json' \
    -d '{"email":"admin@test.local","password":"CorrectHorse42!"}')" "管理员可走后台登录"
ADMIN_ONLY="$(req POST /api/auth/admin/login -H 'Content-Type: application/json' \
    -d '{"email":"plain@test.local","password":"CorrectHorse42!"}')"
[ "$ADMIN_ONLY" = 403 ] || [ "$ADMIN_ONLY" = 401 ] &&
    ok "普通用户走不了后台登录（${ADMIN_ONLY}）" ||
    bad "普通用户走不了后台登录" "竟然返回 ${ADMIN_ONLY}"

# initialize-password 只为「OAuth 建号、尚无密码」的用户设首个密码。
# 已经有密码的账号必须拒绝 —— 否则拿到一个会话就能绕过旧密码校验直接改密。
restart_app
TOK_P="$(login_token plain@test.local "CorrectHorse42!")"
eq 401 "$(req POST /api/auth/initialize-password -H 'Content-Type: application/json' \
    -d '{"password":"BrandNewHorse43!"}')" "initialize-password 需要登录"
STATUS_IP="$(req POST /api/auth/initialize-password -H "Authorization: Bearer ${TOK_P}" \
    -H 'Content-Type: application/json' -d '{"password":"BrandNewHorse43!"}')"
if [ "$STATUS_IP" != 200 ]; then
    ok "已有密码的账号不能走 initialize-password（${STATUS_IP}）"
else
    bad "已有密码的账号不能走 initialize-password" "竟然放行了，等于绕过旧密码校验改密"
fi
# 确认旧密码仍然有效 —— 上面那次调用不得产生任何副作用
restart_app
eq 200 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"plain@test.local","password":"CorrectHorse42!"}')" "被拒的调用没有改掉原密码"

group "22. 不配第三方登录也能独立跑"

# 以前这四个凭证是硬必填，只用邮箱密码的部署被迫在配置里填 dummy ——
# 而配置里的假数据一旦被当真就是事故。这组验「不填也能跑」。
kill -9 "$APP_PID" 2>/dev/null
sleep 0.5
sql "DELETE rate_limit" > /dev/null 2>&1
(
    cd "$ROOT"
    DATABASE_URL="127.0.0.1:${SURREAL_PORT}" \
    DATABASE_USER=root DATABASE_PASS=root \
    DATABASE_NAMESPACE=auth DATABASE_NAME=main \
    JWT_SECRET=0123456789abcdef0123456789abcdef \
    SMTP_HOST=127.0.0.1 SMTP_PORT="${SINK_PORT}" SMTP_FROM=noreply@example.com \
    SMTP_INSECURE=true APP_URL="$APP" \
    BIND_ADDR="127.0.0.1:${APP_PORT}" RUST_LOG=rust_auth=warn \
    exec ./target/debug/rust-auth
) > "$WORK/app_nooauth.log" 2>&1 &
APP_PID=$!
disown "$APP_PID" 2>/dev/null
wait_for "${APP}/api/oidc/jwks" "SoulAuth(无 OAuth 配置)" || {
    bad "不配 GOOGLE_/GITHUB_ 凭证时服务仍能启动" "$(tail -5 "$WORK/app_nooauth.log")"
}

ok "不配 GOOGLE_/GITHUB_ 凭证时服务仍能启动"
eq 200 "$(req POST /api/auth/register -H 'Content-Type: application/json' \
    -d '{"email":"solo@test.local","password":"CorrectHorse42!","username":"solouser"}')" \
    "邮箱密码注册照常可用"
eq 200 "$(req POST /api/auth/login -H 'Content-Type: application/json' \
    -d '{"email":"solo@test.local","password":"CorrectHorse42!"}')" "邮箱密码登录照常可用"
eq 200 "$(req GET /.well-known/openid-configuration)" "OIDC 发现文档照常可用"

# 未配置的 provider：501「本部署没开」，而不是拿假凭证去换令牌后吐 OAuth 错误
eq 501 "$(req GET /api/auth/login/google)" "Google 登录入口 → 501 未启用"
eq 501 "$(req GET /api/auth/login/github)" "GitHub 登录入口 → 501 未启用"
req GET /api/auth/login/google > /dev/null
has 'not enabled' "$(body)" "501 的说明是「本部署未启用」而非 OAuth 库的报错"

restart_app   # 交还给带 dummy 凭证的标准配置

group "23. 运行期无 panic"







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
