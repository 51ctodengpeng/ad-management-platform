# -*- coding: utf-8 -*-
"""RBAC 精细化权限：角色定义 + 模块×操作权限 + 数据范围。

模型：
- 角色（sys_role）：key（唯一标识）、显示名、权限集 permissions（{module: [actions]}）、
  数据范围 scope_type（all=全部域 / custom=指定域）+ scope_domains。
- 内置角色：super_admin（全部权限，不可改）、operator（只读 + 基础操作）。
- 用户通过 sys_user.role 关联角色 key。

权限校验：has_permission(user, module, action) 供路由装饰器/侧边栏使用。
数据范围：user_scope_domains(user) 返回 None（全部域）或 [domain_id]。
"""
import json

from modules import db
from modules.applog import get_logger

log = get_logger('rbac')

# ---------------------------------------------------------------- 权限点定义
# module -> {name, actions}。actions 是各模块支持的操作类型。
MODULES = {
    'dashboard':  {'name': '仪表盘',     'actions': ['view']},
    'domain':     {'name': '多域管理',   'actions': ['view', 'create', 'edit', 'delete']},
    'trust':      {'name': '林间信任',   'actions': ['view', 'create', 'delete']},
    'user':       {'name': '用户管理',   'actions': ['view', 'create', 'edit', 'delete', 'export', 'offboard']},
    'ou':         {'name': '部门 OU',    'actions': ['view', 'create', 'edit', 'delete']},
    'group':      {'name': '用户组',     'actions': ['view', 'create', 'edit', 'delete']},
    'computer':   {'name': '域计算机',   'actions': ['view', 'edit', 'delete']},
    'log':        {'name': '日志审计',   'actions': ['view', 'export', 'maintain']},
    'recycle':    {'name': '回收站',     'actions': ['view', 'restore', 'delete']},
    'alerts':     {'name': '告警中心',   'actions': ['view']},
    'health':     {'name': '健康监控',   'actions': ['view', 'export']},
    'security':   {'name': '安全中心',   'actions': ['view', 'export']},
    'license':    {'name': '授权信息',   'actions': ['view', 'activate']},
    'email_alert': {'name': '邮箱告警',  'actions': ['view', 'manage']},
    'config':     {'name': '系统设置',   'actions': ['view', 'manage']},
}

ACTION_NAMES = {
    'view': '查看', 'create': '新增', 'edit': '修改', 'delete': '删除',
    'export': '导出', 'offboard': '离职处理', 'restore': '还原', 'activate': '激活',
    'manage': '管理', 'maintain': '维护',
}

BUILTIN_ROLES = {
    'super_admin': {
        'display_name': '超级管理员',
        'description': '拥有全部功能与数据权限（内置，不可修改）',
        'permissions': {m: list(v['actions']) for m, v in MODULES.items()},
        'scope_type': 'all', 'scope_domains': [],
    },
    'operator': {
        'display_name': '普通运维',
        'description': '只读 + 日常增删改（不含系统设置、授权、日志维护等敏感操作）',
        'permissions': {
            'dashboard': ['view'], 'domain': ['view'], 'trust': ['view'],
            'user': ['view', 'create', 'edit', 'export'], 'ou': ['view', 'create', 'edit'],
            'group': ['view', 'create', 'edit'], 'computer': ['view', 'edit'],
            'log': ['view'], 'alerts': ['view'], 'health': ['view'],
            'recycle': ['view', 'restore'],
        },
        'scope_type': 'all', 'scope_domains': [],
    },
}


def ensure_builtin_roles() -> None:
    """种子内置角色（幂等）。启动时调用。"""
    for key, cfg in BUILTIN_ROLES.items():
        row = db.query_one('SELECT id, permissions FROM sys_role WHERE key=?', (key,))
        if not row:
            db.execute("INSERT INTO sys_role(key, display_name, description, is_builtin, permissions, "
                       "scope_type, scope_domains) VALUES(?,?,?,1,?,?,?)",
                       (key, cfg['display_name'], cfg['description'],
                        json.dumps(cfg['permissions'], ensure_ascii=False),
                        cfg['scope_type'], json.dumps(cfg['scope_domains'])))
        else:
            # 内置角色权限固定，始终以代码为准（防止被外部改乱）
            db.execute("UPDATE sys_role SET display_name=?, description=?, permissions=?, "
                       "scope_type='all', scope_domains='[]', is_builtin=1 WHERE key=?",
                       (cfg['display_name'], cfg['description'],
                        json.dumps(cfg['permissions'], ensure_ascii=False), key))


# ---------------------------------------------------------------- 角色 CRUD
def list_roles() -> list:
    rows = db.query('SELECT * FROM sys_role ORDER BY is_builtin DESC, id')
    out = []
    for r in rows:
        d = dict(r)
        d['permissions'] = _load_json(d.get('permissions'), {})
        d['scope_domains'] = _load_json(d.get('scope_domains'), [])
        out.append(d)
    return out


def get_role(key: str) -> dict | None:
    row = db.query_one('SELECT * FROM sys_role WHERE key=?', (key,))
    if not row:
        return None
    d = dict(row)
    d['permissions'] = _load_json(d.get('permissions'), {})
    d['scope_domains'] = _load_json(d.get('scope_domains'), [])
    return d


def create_role(key: str, display_name: str, description: str, permissions: dict,
                scope_type: str, scope_domains: list) -> int:
    key = (key or '').strip()
    if not key or len(key) < 2:
        raise ValueError('角色标识至少 2 个字符')
    if not re_fullmatch_key(key):
        raise ValueError('角色标识仅限字母数字下划线')
    if db.query_one('SELECT 1 FROM sys_role WHERE key=?', (key,)):
        raise ValueError('角色标识已存在')
    if scope_type not in ('all', 'custom'):
        raise ValueError('数据范围不合法')
    return db.insert(
        "INSERT INTO sys_role(key, display_name, description, is_builtin, permissions, scope_type, scope_domains) "
        "VALUES(?,?,?,0,?,?,?)",
        (key, display_name or key, description or '',
         json.dumps(_sanitize_permissions(permissions), ensure_ascii=False),
         scope_type, json.dumps([int(x) for x in (scope_domains or [])])))


def update_role(key: str, display_name: str, description: str, permissions: dict,
                scope_type: str, scope_domains: list) -> None:
    row = db.query_one('SELECT id, is_builtin FROM sys_role WHERE key=?', (key,))
    if not row:
        raise ValueError('角色不存在')
    if row['is_builtin']:
        raise ValueError('内置角色不可修改')
    if scope_type not in ('all', 'custom'):
        raise ValueError('数据范围不合法')
    db.execute(
        "UPDATE sys_role SET display_name=?, description=?, permissions=?, scope_type=?, "
        "scope_domains=?, updated_at=datetime('now','localtime') WHERE key=?",
        (display_name or key, description or '',
         json.dumps(_sanitize_permissions(permissions), ensure_ascii=False),
         scope_type, json.dumps([int(x) for x in (scope_domains or [])]), key))


def delete_role(key: str) -> None:
    row = db.query_one('SELECT id, is_builtin FROM sys_role WHERE key=?', (key,))
    if not row:
        raise ValueError('角色不存在')
    if row['is_builtin']:
        raise ValueError('内置角色不可删除')
    # 仍在使用该角色的用户回退为 operator
    db.execute("UPDATE sys_user SET role='operator' WHERE role=?", (key,))
    db.execute('DELETE FROM sys_role WHERE key=?', (key,))


def _load_json(s, default):
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def _sanitize_permissions(permissions: dict) -> dict:
    """过滤非法模块/操作，只保留合法权限点。"""
    out = {}
    for m, acts in (permissions or {}).items():
        if m not in MODULES:
            continue
        valid = [a for a in acts if a in MODULES[m]['actions']]
        if valid:
            out[m] = valid
    return out


def re_fullmatch_key(s: str) -> bool:
    import re
    return bool(re.fullmatch(r'[A-Za-z0-9_]{2,32}', s))


# ---------------------------------------------------------------- 权限校验
def _all_permissions() -> dict:
    return {m: list(v['actions']) for m, v in MODULES.items()}


def user_role(user) -> dict | None:
    """当前用户的角色定义（超级管理员恒返回全部权限）。"""
    if not user:
        return None
    user = dict(user)
    key = user.get('role') or 'operator'
    if key == 'super_admin':
        return {'key': key, 'display_name': '超级管理员', 'is_builtin': True,
                'permissions': _all_permissions(), 'scope_type': 'all', 'scope_domains': []}
    return get_role(key)


def has_permission(user, module: str, action: str = 'view') -> bool:
    """判断用户是否有某模块的某操作权限。"""
    role = user_role(user)
    if not role:
        return False
    perms = role.get('permissions') or {}
    acts = perms.get(module, [])
    return action in acts or 'manage' in acts


def user_scope_domains(user) -> list | None:
    """用户的数据范围：None=全部域，[domain_id]=仅这些域。超级管理员=全部。"""
    role = user_role(user)
    if not role:
        return []
    if role.get('scope_type') == 'all':
        return None
    return role.get('scope_domains') or []


def visible_domains(user):
    """按数据范围返回用户可访问的域列表（L.load_domains 过滤）。"""
    from modules import ad_ldap as L
    domains = L.load_domains()
    scope = user_scope_domains(user)
    if scope is None:
        return domains
    ids = set(scope)
    return [d for d in domains if d.id in ids]
