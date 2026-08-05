-- Rainbow-Docs 权限扩展
-- 为 Rainbow-Auth 系统添加文档管理相关权限
-- 在执行 initial_data.sql 之后运行此文件

-- 文档管理权限
UPSERT permission:docs_read CONTENT {
    name: "docs.read",
    display_name: "查看文档",
    description: "查看和阅读文档内容",
    resource: "documents",
    action: "read",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

UPSERT permission:docs_write CONTENT {
    name: "docs.write",
    display_name: "编辑文档",
    description: "创建、编辑和发布文档",
    resource: "documents",
    action: "write",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

UPSERT permission:docs_delete CONTENT {
    name: "docs.delete",
    display_name: "删除文档",
    description: "删除文档和章节",
    resource: "documents",
    action: "delete",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

UPSERT permission:docs_admin CONTENT {
    name: "docs.admin",
    display_name: "文档管理",
    description: "管理文档空间、权限和设置",
    resource: "documents",
    action: "admin",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

-- 文档空间权限
UPSERT permission:spaces_read CONTENT {
    name: "spaces.read",
    display_name: "查看文档空间",
    description: "查看和访问文档空间",
    resource: "spaces",
    action: "read",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

UPSERT permission:spaces_write CONTENT {
    name: "spaces.write",
    display_name: "管理文档空间",
    description: "创建、编辑文档空间和设置",
    resource: "spaces",
    action: "write",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

UPSERT permission:spaces_delete CONTENT {
    name: "spaces.delete",
    display_name: "删除文档空间",
    description: "删除文档空间",
    resource: "spaces",
    action: "delete",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

-- 文档评论权限
UPSERT permission:comments_read CONTENT {
    name: "comments.read",
    display_name: "查看评论",
    description: "查看文档评论和讨论",
    resource: "comments",
    action: "read",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

UPSERT permission:comments_write CONTENT {
    name: "comments.write",
    display_name: "管理评论",
    description: "添加、编辑和回复评论",
    resource: "comments",
    action: "write",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

UPSERT permission:comments_delete CONTENT {
    name: "comments.delete",
    display_name: "删除评论",
    description: "删除评论和讨论",
    resource: "comments",
    action: "delete",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

-- 创建文档管理员角色
UPSERT role:docs_admin CONTENT {
    name: "docs_admin",
    display_name: "文档管理员",
    description: "拥有完整文档管理权限的管理员",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

-- 创建文档编辑员角色
UPSERT role:docs_editor CONTENT {
    name: "docs_editor",
    display_name: "文档编辑员",
    description: "可以创建和编辑文档的角色",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

-- 创建文档阅读者角色
UPSERT role:docs_reader CONTENT {
    name: "docs_reader",
    display_name: "文档阅读者",
    description: "只能查看文档的角色",
    is_system: true,
    created_at: time::unix(),
    updated_at: time::unix()
};

-- 为 admin 角色添加所有文档权限
UPSERT role_permission:admin__docs_read CONTENT {
    role_id: role:admin,
    permission_id: permission:docs_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:admin__docs_write CONTENT {
    role_id: role:admin,
    permission_id: permission:docs_write,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:admin__docs_delete CONTENT {
    role_id: role:admin,
    permission_id: permission:docs_delete,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:admin__docs_admin CONTENT {
    role_id: role:admin,
    permission_id: permission:docs_admin,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:admin__spaces_read CONTENT {
    role_id: role:admin,
    permission_id: permission:spaces_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:admin__spaces_write CONTENT {
    role_id: role:admin,
    permission_id: permission:spaces_write,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:admin__spaces_delete CONTENT {
    role_id: role:admin,
    permission_id: permission:spaces_delete,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:admin__comments_read CONTENT {
    role_id: role:admin,
    permission_id: permission:comments_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:admin__comments_write CONTENT {
    role_id: role:admin,
    permission_id: permission:comments_write,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:admin__comments_delete CONTENT {
    role_id: role:admin,
    permission_id: permission:comments_delete,
    granted_at: time::unix(),
    granted_by: user:system
};

-- 为 docs_admin 角色分配文档管理权限
UPSERT role_permission:docs_admin__docs_read CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:docs_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_admin__docs_write CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:docs_write,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_admin__docs_delete CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:docs_delete,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_admin__docs_admin CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:docs_admin,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_admin__spaces_read CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:spaces_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_admin__spaces_write CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:spaces_write,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_admin__spaces_delete CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:spaces_delete,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_admin__comments_read CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:comments_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_admin__comments_write CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:comments_write,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_admin__comments_delete CONTENT {
    role_id: role:docs_admin,
    permission_id: permission:comments_delete,
    granted_at: time::unix(),
    granted_by: user:system
};

-- 为 docs_editor 角色分配编辑权限
UPSERT role_permission:docs_editor__docs_read CONTENT {
    role_id: role:docs_editor,
    permission_id: permission:docs_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_editor__docs_write CONTENT {
    role_id: role:docs_editor,
    permission_id: permission:docs_write,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_editor__spaces_read CONTENT {
    role_id: role:docs_editor,
    permission_id: permission:spaces_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_editor__comments_read CONTENT {
    role_id: role:docs_editor,
    permission_id: permission:comments_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_editor__comments_write CONTENT {
    role_id: role:docs_editor,
    permission_id: permission:comments_write,
    granted_at: time::unix(),
    granted_by: user:system
};

-- 为 docs_reader 角色分配只读权限
UPSERT role_permission:docs_reader__docs_read CONTENT {
    role_id: role:docs_reader,
    permission_id: permission:docs_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_reader__spaces_read CONTENT {
    role_id: role:docs_reader,
    permission_id: permission:spaces_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:docs_reader__comments_read CONTENT {
    role_id: role:docs_reader,
    permission_id: permission:comments_read,
    granted_at: time::unix(),
    granted_by: user:system
};

-- 为 user 角色添加基础文档读取权限
UPSERT role_permission:user__docs_read CONTENT {
    role_id: role:user,
    permission_id: permission:docs_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:user__spaces_read CONTENT {
    role_id: role:user,
    permission_id: permission:spaces_read,
    granted_at: time::unix(),
    granted_by: user:system
};

UPSERT role_permission:user__comments_read CONTENT {
    role_id: role:user,
    permission_id: permission:comments_read,
    granted_at: time::unix(),
    granted_by: user:system
};