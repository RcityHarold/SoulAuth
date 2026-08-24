-- Rust Auth System Initial Data
-- 运行此文件以创建系统角色和权限的初始数据

-- 创建系统权限
-- 用户管理权限
UPSERT permission:users_read CONTENT {
    name: "soulauth:users.read",
    display_name: "查看用户",
    description: "查看用户信息",
    resource: "users",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

UPSERT permission:users_write CONTENT {
    name: "soulauth:users.write",
    display_name: "编辑用户",
    description: "编辑用户信息",
    resource: "users",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 角色管理权限
UPSERT permission:roles_read CONTENT {
    name: "soulauth:roles.read",
    display_name: "查看角色",
    description: "查看角色信息",
    resource: "roles",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

UPSERT permission:roles_write CONTENT {
    name: "soulauth:roles.write",
    display_name: "管理角色",
    description: "创建和编辑角色",
    resource: "roles",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

UPSERT permission:roles_delete CONTENT {
    name: "soulauth:roles.delete",
    display_name: "删除角色",
    description: "删除角色",
    resource: "roles",
    action: "delete",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 权限管理权限
UPSERT permission:permissions_read CONTENT {
    name: "soulauth:permissions.read",
    display_name: "查看权限",
    description: "查看权限信息",
    resource: "permissions",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

UPSERT permission:permissions_write CONTENT {
    name: "soulauth:permissions.write",
    display_name: "管理权限",
    description: "创建和编辑权限",
    resource: "permissions",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 安全管理权限
UPSERT permission:security_read CONTENT {
    name: "soulauth:security.read",
    display_name: "查看安全状态",
    description: "查看安全锁定状态",
    resource: "security",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

UPSERT permission:security_write CONTENT {
    name: "soulauth:security.write",
    display_name: "管理安全",
    description: "解锁账户等安全操作",
    resource: "security",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 审计权限
UPSERT permission:audit_read CONTENT {
    name: "soulauth:audit.read",
    display_name: "查看审计日志",
    description: "查看系统审计日志",
    resource: "audit",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 用户档案管理权限

-- 用户偏好设置权限

-- 创建系统角色
-- 系统管理员角色
UPSERT role:admin CONTENT {
    name: "admin",
    display_name: "系统管理员",
    description: "拥有所有权限的系统管理员",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 用户管理员角色
UPSERT role:user_manager CONTENT {
    name: "user_manager",
    display_name: "用户管理员",
    description: "负责用户管理的管理员",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 安全管理员角色
UPSERT role:security_manager CONTENT {
    name: "security_manager",
    display_name: "安全管理员",
    description: "负责安全管理的管理员",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 审计员角色
UPSERT role:auditor CONTENT {
    name: "auditor",
    display_name: "审计员",
    description: "只能查看审计日志的角色",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 普通用户角色
UPSERT role:user CONTENT {
    name: "user",
    display_name: "普通用户",
    description: "普通用户角色",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 为系统用户创建记录（用于权限分配的授权者）
-- 注意：UPSERT ... CONTENT 会整条替换记录，而 DEFAULT 只在创建时生效。
-- 因此凡是 TYPE 非 option 的字段都必须在这里显式写出，
-- 否则第二次导入时该字段变成 NONE，直接撞类型校验。
UPSERT user:system CONTENT {
    email: "system@internal",
    username: "system",
    username_normalized: "system",
    password: NONE,
    verified: true,
    verification_token: NONE,
    verification_token_expires_at: NONE,
    account_status: "Active",
    membership_level: "FREE",
    membership_expiry: NONE,
    last_login_at: NONE,
    last_login_ip: NONE,
    created_at: 0,
    updated_at: 0
};

-- 为admin角色分配所有权限
UPSERT role_permission:admin__users_read CONTENT {
    role_id: role:admin,
    permission_id: permission:users_read,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__users_write CONTENT {
    role_id: role:admin,
    permission_id: permission:users_write,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__roles_read CONTENT {
    role_id: role:admin,
    permission_id: permission:roles_read,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__roles_write CONTENT {
    role_id: role:admin,
    permission_id: permission:roles_write,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__roles_delete CONTENT {
    role_id: role:admin,
    permission_id: permission:roles_delete,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__permissions_read CONTENT {
    role_id: role:admin,
    permission_id: permission:permissions_read,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__permissions_write CONTENT {
    role_id: role:admin,
    permission_id: permission:permissions_write,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__security_read CONTENT {
    role_id: role:admin,
    permission_id: permission:security_read,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__security_write CONTENT {
    role_id: role:admin,
    permission_id: permission:security_write,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__audit_read CONTENT {
    role_id: role:admin,
    permission_id: permission:audit_read,
    granted_at: 0,
    granted_by: user:system
};

-- 为user_manager角色分配用户管理权限
UPSERT role_permission:user_manager__users_read CONTENT {
    role_id: role:user_manager,
    permission_id: permission:users_read,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:user_manager__users_write CONTENT {
    role_id: role:user_manager,
    permission_id: permission:users_write,
    granted_at: 0,
    granted_by: user:system
};

-- 为security_manager角色分配安全管理权限
UPSERT role_permission:security_manager__security_read CONTENT {
    role_id: role:security_manager,
    permission_id: permission:security_read,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:security_manager__security_write CONTENT {
    role_id: role:security_manager,
    permission_id: permission:security_write,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:security_manager__users_read CONTENT {
    role_id: role:security_manager,
    permission_id: permission:users_read,
    granted_at: 0,
    granted_by: user:system
};

-- 为auditor角色分配审计权限
UPSERT role_permission:auditor__audit_read CONTENT {
    role_id: role:auditor,
    permission_id: permission:audit_read,
    granted_at: 0,
    granted_by: user:system
};

-- ===============================
-- OIDC 客户端管理权限（新增）
-- ===============================
-- /api/oidc/clients 以前完全没有鉴权，任何人都能创建 / 改写 OIDC 客户端。
-- 现在读写分别要求下面两个权限，默认只授予 admin 角色。
-- 对已有部署：单独执行本段即可完成迁移。

UPSERT permission:oidc_clients_read CONTENT {
    name: "soulauth:oidc_clients.read",
    display_name: "查看 OIDC 客户端",
    description: "查看已注册的 OIDC 客户端配置",
    resource: "oidc_clients",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

UPSERT permission:oidc_clients_write CONTENT {
    name: "soulauth:oidc_clients.write",
    display_name: "管理 OIDC 客户端",
    description: "创建、修改、禁用 OIDC 客户端并重置其密钥",
    resource: "oidc_clients",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

UPSERT role_permission:admin__oidc_clients_read CONTENT {
    role_id: role:admin,
    permission_id: permission:oidc_clients_read,
    granted_at: 0,
    granted_by: user:system
};

UPSERT role_permission:admin__oidc_clients_write CONTENT {
    role_id: role:admin,
    permission_id: permission:oidc_clients_write,
    granted_at: 0,
    granted_by: user:system
};
