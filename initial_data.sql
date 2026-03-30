-- Rust Auth System Initial Data
-- 运行此文件以创建系统角色和权限的初始数据

-- 创建系统权限
-- 用户管理权限
CREATE permission:users_read CONTENT {
    name: "users.read",
    display_name: "查看用户",
    description: "查看用户信息",
    resource: "users",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

CREATE permission:users_write CONTENT {
    name: "users.write",
    display_name: "编辑用户",
    description: "编辑用户信息",
    resource: "users",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

CREATE permission:users_delete CONTENT {
    name: "users.delete",
    display_name: "删除用户",
    description: "删除用户账户",
    resource: "users",
    action: "delete",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 角色管理权限
CREATE permission:roles_read CONTENT {
    name: "roles.read",
    display_name: "查看角色",
    description: "查看角色信息",
    resource: "roles",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

CREATE permission:roles_write CONTENT {
    name: "roles.write",
    display_name: "管理角色",
    description: "创建和编辑角色",
    resource: "roles",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

CREATE permission:roles_delete CONTENT {
    name: "roles.delete",
    display_name: "删除角色",
    description: "删除角色",
    resource: "roles",
    action: "delete",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 权限管理权限
CREATE permission:permissions_read CONTENT {
    name: "permissions.read",
    display_name: "查看权限",
    description: "查看权限信息",
    resource: "permissions",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

CREATE permission:permissions_write CONTENT {
    name: "permissions.write",
    display_name: "管理权限",
    description: "创建和编辑权限",
    resource: "permissions",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

CREATE permission:permissions_delete CONTENT {
    name: "permissions.delete",
    display_name: "删除权限",
    description: "删除权限",
    resource: "permissions",
    action: "delete",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 安全管理权限
CREATE permission:security_read CONTENT {
    name: "security.read",
    display_name: "查看安全状态",
    description: "查看安全锁定状态",
    resource: "security",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

CREATE permission:security_write CONTENT {
    name: "security.write",
    display_name: "管理安全",
    description: "解锁账户等安全操作",
    resource: "security",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 审计权限
CREATE permission:audit_read CONTENT {
    name: "audit.read",
    display_name: "查看审计日志",
    description: "查看系统审计日志",
    resource: "audit",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 用户档案管理权限
CREATE permission:profile_read CONTENT {
    name: "profile.read",
    display_name: "查看用户档案",
    description: "查看用户档案信息",
    resource: "profile",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

CREATE permission:profile_write CONTENT {
    name: "profile.write",
    display_name: "管理用户档案",
    description: "创建和编辑用户档案",
    resource: "profile",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 用户偏好设置权限
CREATE permission:preferences_read CONTENT {
    name: "preferences.read",
    display_name: "查看用户偏好",
    description: "查看用户偏好设置",
    resource: "preferences",
    action: "read",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

CREATE permission:preferences_write CONTENT {
    name: "preferences.write",
    display_name: "管理用户偏好",
    description: "创建和编辑用户偏好设置",
    resource: "preferences",
    action: "write",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 创建系统角色
-- 系统管理员角色
CREATE role:admin CONTENT {
    name: "admin",
    display_name: "系统管理员",
    description: "拥有所有权限的系统管理员",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 用户管理员角色
CREATE role:user_manager CONTENT {
    name: "user_manager",
    display_name: "用户管理员",
    description: "负责用户管理的管理员",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 安全管理员角色
CREATE role:security_manager CONTENT {
    name: "security_manager",
    display_name: "安全管理员",
    description: "负责安全管理的管理员",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 审计员角色
CREATE role:auditor CONTENT {
    name: "auditor",
    display_name: "审计员",
    description: "只能查看审计日志的角色",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 普通用户角色
CREATE role:user CONTENT {
    name: "user",
    display_name: "普通用户",
    description: "普通用户角色",
    is_system: true,
    created_at: 0,
    updated_at: 0
};

-- 为系统用户创建记录（用于权限分配的授权者）
CREATE user:system CONTENT {
    email: "system@internal",
    username: "system",
    username_normalized: "system",
    password: NONE,
    verified: true,
    verification_token: NONE,
    account_status: "Active",
    last_login_at: NONE,
    last_login_ip: NONE,
    created_at: 0,
    updated_at: 0
};

-- 为admin角色分配所有权限
CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:users_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:users_write,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:users_delete,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:roles_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:roles_write,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:roles_delete,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:permissions_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:permissions_write,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:permissions_delete,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:security_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:security_write,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:audit_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:profile_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:profile_write,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:preferences_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:admin,
    permission_id: permission:preferences_write,
    granted_at: 0,
    granted_by: user:system
};

-- 为user_manager角色分配用户管理权限
CREATE role_permission CONTENT {
    role_id: role:user_manager,
    permission_id: permission:users_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:user_manager,
    permission_id: permission:users_write,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:user_manager,
    permission_id: permission:users_delete,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:user_manager,
    permission_id: permission:profile_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:user_manager,
    permission_id: permission:profile_write,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:user_manager,
    permission_id: permission:preferences_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:user_manager,
    permission_id: permission:preferences_write,
    granted_at: 0,
    granted_by: user:system
};

-- 为security_manager角色分配安全管理权限
CREATE role_permission CONTENT {
    role_id: role:security_manager,
    permission_id: permission:security_read,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:security_manager,
    permission_id: permission:security_write,
    granted_at: 0,
    granted_by: user:system
};

CREATE role_permission CONTENT {
    role_id: role:security_manager,
    permission_id: permission:users_read,
    granted_at: 0,
    granted_by: user:system
};

-- 为auditor角色分配审计权限
CREATE role_permission CONTENT {
    role_id: role:auditor,
    permission_id: permission:audit_read,
    granted_at: 0,
    granted_by: user:system
};
