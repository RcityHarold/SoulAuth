# OIDC 单点登录部署和使用指南

## 概述

Rainbow-Auth 系统实现了完整的 OpenID Connect 1.0 协议，支持企业级单点登录 (SSO) 功能。本指南详细说明如何部署、配置和使用 OIDC 功能。

## 特性概览

### 🔐 协议支持
- **OpenID Connect 1.0**: 完整的 OIDC 协议实现
- **OAuth 2.0**: 标准的授权码流程
- **PKCE**: 代码质询扩展，防止授权码拦截
- **JWT**: 标准的 JSON Web Token 实现

### 🏢 企业级功能
- **多客户端支持**: Web 应用、SPA、移动应用
- **单点登录**: 跨应用的无缝身份验证
- **单点登出**: 全局和单应用登出支持
- **会话管理**: 完整的 SSO 会话生命周期

### 🛡️ 安全特性
- **客户端认证**: 支持机密和公开客户端
- **作用域控制**: 细粒度的权限管理
- **令牌管理**: 访问、刷新、ID 令牌
- **签名验证**: JWT 签名和验证

## 快速开始

### 1. 数据库初始化

首先确保运行数据库架构脚本：

```bash
# 使用 SurrealDB CLI 或者通过 HTTP API 执行
surreal import --conn http://localhost:8000 --user root --pass root --ns auth --db main schema.sql
```

### 2. 启动服务

```bash
cargo run
```

### 3. 验证 OIDC 配置

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

## 客户端注册

### 创建 OIDC 客户端

```bash
curl -X POST http://localhost:8080/api/oidc/clients \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "我的应用",
    "client_type": "confidential",
    "redirect_uris": ["https://myapp.com/callback"],
    "post_logout_redirect_uris": ["https://myapp.com/logout"],
    "allowed_scopes": ["openid", "profile", "email"],
    "require_pkce": true
  }'
```

响应示例：
```json
{
  "client_id": "client_1634567890abc123def",
  "client_secret": "a1b2c3d4e5f6g7h8i9j0...",
  "client_name": "我的应用",
  "client_type": "confidential",
  "redirect_uris": ["https://myapp.com/callback"],
  "allowed_scopes": ["openid", "profile", "email"],
  "require_pkce": true
}
```

**重要**: 保存 `client_secret`，它只在创建时返回一次。

### 客户端类型

- **confidential**: 机密客户端，能够安全存储客户端密钥
- **public**: 公开客户端，如 SPA 或移动应用

## OIDC 集成流程

### 授权码流程 (推荐)

#### 步骤 1: 重定向到授权端点

```javascript
// 生成 PKCE 参数
const codeVerifier = generateCodeVerifier(); // 43-128 字符的随机字符串
const codeChallenge = base64URLEncode(sha256(codeVerifier));

// 构建授权 URL
const authUrl = new URL('http://localhost:8080/api/oidc/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your_client_id');
authUrl.searchParams.set('redirect_uri', 'https://myapp.com/callback');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', generateRandomState());
authUrl.searchParams.set('nonce', generateRandomNonce());
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

// 重定向用户
window.location.href = authUrl.toString();
```

#### 步骤 2: 处理回调

```javascript
// 在回调页面处理授权码
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

// 验证 state 参数
if (state !== sessionStorage.getItem('oauth_state')) {
  throw new Error('Invalid state parameter');
}
```

#### 步骤 3: 交换令牌

```javascript
const tokenResponse = await fetch('http://localhost:8080/api/oidc/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: 'https://myapp.com/callback',
    client_id: 'your_client_id',
    client_secret: 'your_client_secret', // 仅机密客户端
    code_verifier: codeVerifier
  })
});

const tokens = await tokenResponse.json();
// tokens.access_token, tokens.id_token, tokens.refresh_token
```

#### 步骤 4: 获取用户信息

```javascript
const userInfoResponse = await fetch('http://localhost:8080/api/oidc/userinfo', {
  headers: {
    'Authorization': `Bearer ${tokens.access_token}`
  }
});

const userInfo = await userInfoResponse.json();
console.log(userInfo);
```

## 令牌管理

### 刷新访问令牌

```javascript
const refreshResponse = await fetch('http://localhost:8080/api/oidc/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: storedRefreshToken,
    client_id: 'your_client_id',
    client_secret: 'your_client_secret'
  })
});

const newTokens = await refreshResponse.json();
```

### 令牌验证

```javascript
// 解码 ID Token (仅用于读取声明，不用于验证)
const idTokenPayload = JSON.parse(atob(idToken.split('.')[1]));
console.log('User ID:', idTokenPayload.sub);
console.log('Email:', idTokenPayload.email);
```

## 单点登出

### 发起登出

```javascript
const logoutUrl = new URL('http://localhost:8080/api/oidc/logout');
logoutUrl.searchParams.set('post_logout_redirect_uri', 'https://myapp.com/logout');
logoutUrl.searchParams.set('id_token_hint', idToken);
logoutUrl.searchParams.set('state', generateRandomState());

window.location.href = logoutUrl.toString();
```

### 处理登出回调

```javascript
// 在登出回调页面
const urlParams = new URLSearchParams(window.location.search);
const state = urlParams.get('state');

// 清理本地存储
localStorage.removeItem('access_token');
localStorage.removeItem('refresh_token');
localStorage.removeItem('id_token');

// 重定向到首页
window.location.href = '/';
```

## 客户端库集成

### JavaScript/Node.js

推荐使用 `openid-client` 库：

```javascript
const { Issuer, Strategy } = require('openid-client');

// 发现 OIDC 配置
const rainbowAuthIssuer = await Issuer.discover('http://localhost:8080');

// 创建客户端
const client = new rainbowAuthIssuer.Client({
  client_id: 'your_client_id',
  client_secret: 'your_client_secret',
  redirect_uris: ['https://myapp.com/callback'],
  response_types: ['code'],
});

// 生成授权 URL
const authUrl = client.authorizationUrl({
  scope: 'openid profile email',
  code_challenge_method: 'S256',
});
```

### React 示例

```jsx
import { useEffect, useState } from 'react';

function OIDCLogin() {
  const [user, setUser] = useState(null);
  
  const login = () => {
    const authUrl = new URL('http://localhost:8080/api/oidc/authorize');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', process.env.REACT_APP_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', `${window.location.origin}/callback`);
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('state', Math.random().toString(36));
    
    window.location.href = authUrl.toString();
  };
  
  const handleCallback = async (code) => {
    const response = await fetch('http://localhost:8080/api/oidc/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${window.location.origin}/callback`,
        client_id: process.env.REACT_APP_CLIENT_ID,
        client_secret: process.env.REACT_APP_CLIENT_SECRET,
      })
    });
    
    const tokens = await response.json();
    localStorage.setItem('access_token', tokens.access_token);
    
    // 获取用户信息
    const userResponse = await fetch('http://localhost:8080/api/oidc/userinfo', {
      headers: { 'Authorization': `Bearer ${tokens.access_token}` }
    });
    
    const userInfo = await userResponse.json();
    setUser(userInfo);
  };
  
  return (
    <div>
      {user ? (
        <div>欢迎, {user.name || user.email}!</div>
      ) : (
        <button onClick={login}>登录</button>
      )}
    </div>
  );
}
```

## 高级配置

### 客户端配置选项

```json
{
  "client_name": "应用名称",
  "client_type": "confidential",
  "redirect_uris": [
    "https://app.example.com/callback",
    "https://app.example.com/silent-renew"
  ],
  "post_logout_redirect_uris": [
    "https://app.example.com/logout"
  ],
  "allowed_scopes": ["openid", "profile", "email"],
  "allowed_grant_types": ["authorization_code", "refresh_token"],
  "allowed_response_types": ["code"],
  "require_pkce": true,
  "access_token_lifetime": 3600,
  "refresh_token_lifetime": 86400,
  "id_token_lifetime": 3600
}
```

### 作用域说明

- **openid**: 必需，表示这是 OIDC 请求
- **profile**: 访问基本档案信息 (name, preferred_username)
- **email**: 访问邮箱信息 (email, email_verified)

### 安全建议

1. **使用 HTTPS**: 生产环境必须使用 HTTPS
2. **验证重定向 URI**: 严格验证重定向 URI
3. **使用 PKCE**: 对所有客户端启用 PKCE
4. **令牌存储**: 安全存储刷新令牌
5. **状态验证**: 始终验证 state 参数

## 故障排除

### 常见错误

#### 1. `invalid_client`
- 检查 client_id 和 client_secret
- 确认客户端处于活跃状态

#### 2. `invalid_redirect_uri`
- 确保重定向 URI 完全匹配注册的 URI
- 检查 HTTPS/HTTP 协议

#### 3. `invalid_grant`
- 授权码可能已过期或已使用
- PKCE 验证失败

#### 4. `access_denied`
- 用户拒绝授权
- 用户账户被锁定或禁用

### 调试技巧

1. **检查 Discovery 端点**:
   ```bash
   curl http://localhost:8080/.well-known/openid-configuration
   ```

2. **验证 JWT 令牌**:
   使用 [jwt.io](https://jwt.io) 解码 ID Token

3. **查看服务器日志**:
   检查 Rainbow-Auth 服务器日志获取详细错误信息

## 监控和维护

### 会话监控

```bash
# 查看本人的活跃会话（每条含 IP / User-Agent / 是否当前会话）
curl http://localhost:8080/api/auth/sessions \
  -H "Authorization: Bearer user-token"
```

会话吊销是自动的：登出、全端登出、改密、以及管理员停用账号，
都会删掉服务端 `session` 行并吊销该用户已签发的 OIDC 访问 / 刷新令牌。

### 客户端管理

```bash
# 列出所有客户端
curl http://localhost:8080/api/oidc/clients \
  -H "Authorization: Bearer admin-token"

# 重新生成客户端密钥
curl -X POST http://localhost:8080/api/oidc/clients/client123/regenerate-secret \
  -H "Authorization: Bearer admin-token"
```

### 清理过期数据

服务内置后台任务，每小时清理一次过期的会话、授权码、OIDC 令牌、
限流计数与账号锁定记录，无需手工触发。

## 生产部署注意事项

1. **环境变量**: 确保所有敏感配置通过环境变量设置
2. **密钥管理**: 使用强随机密钥，定期轮换
3. **负载均衡**: 配置会话亲和性或使用共享存储
4. **监控**: 设置会话和令牌的监控告警
5. **备份**: 定期备份客户端配置和会话数据

## 参考资源

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)