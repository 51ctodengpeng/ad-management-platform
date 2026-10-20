# -*- coding: utf-8 -*-
"""缓存查询层：用户/OU/组/计算机的列表、搜索、筛选、分页（全部读 SQLite，禁止实时查 AD）"""
import re

import config
from modules import db
from modules import ad_ldap as L

USER_SORTABLE = {
    'sam': 'sam_account_name', 'name': 'display_name', 'dept': 'department',
    'created': 'when_created', 'logon': 'last_logon', 'ou': 'ou_dn', 'status': 'enabled',
}


def _tag_conditions(tag: str, prefix: str = '') -> tuple:
    """快捷筛选标签 → SQL 片段。"""
    def col(c):
        return f'{prefix}{c}'
    now = "datetime('now','localtime')"
    if tag == 'disabled':
        return f'{col("enabled")}=0', []
    if tag == 'locked':
        return f'{col("locked")}=1', []
    if tag == 'pwd_expired':
        return f"{col('pwd_expires_at')}<>'' AND {col('pwd_expires_at')}<=datetime('now','localtime')", []
    if tag == 'pwd_soon':
        return (f"{col('pwd_expires_at')}<>'' AND {col('pwd_expires_at')}>{now} "
                f"AND {col('pwd_expires_at')}<=datetime('now','localtime','+14 days')"), []
    if tag == 'never_logon':
        return f"({col('last_logon')}='' OR {col('last_logon')} IS NULL)", []
    if tag == 'idle_90':
        return f"{col('last_logon')}<>'' AND {col('last_logon')}<datetime('now','localtime','-90 days')", []
    if tag == 'no_pwd':
        return f"({col('pwd_last_set')}='' OR {col('pwd_last_set')}='从未设置')", []
    return '', []


def search_users(filters: dict, page: int = 1, page_size: int = 20, sort: str = 'sam', order: str = 'asc'):
    where, params = [], []
    domain_id = filters.get('domain_id')
    if domain_id:
        where.append('u.domain_id=?')
        params.append(int(domain_id))
    kw = (filters.get('keyword') or '').strip()
    if kw:
        like = f'%{kw}%'
        where.append('(u.sam_account_name LIKE ? OR u.display_name LIKE ? OR u.mail LIKE ? OR '
                     'u.user_principal_name LIKE ? OR u.description LIKE ? OR u.dn LIKE ?)')
        params += [like] * 6
    if filters.get('enabled') not in (None, '', 'all'):
        where.append('u.enabled=?')
        params.append(int(filters['enabled']))
    if filters.get('department'):
        where.append('u.department=?')
        params.append(filters['department'])
    if filters.get('ou_dn'):
        # 支持整棵子树（DN 中的 _ / % 需转义，否则 OU=IT_01 会误匹配 OU=IT101）
        where.append("(u.ou_dn=? OR u.ou_dn LIKE ? ESCAPE '\\')")
        params += [filters['ou_dn'], db.dn_like(filters['ou_dn'])]
    tag = filters.get('tag')
    if tag:
        frag, extra = _tag_conditions(tag, prefix='u.')
        if frag:
            where.append(f'({frag})')
            params += extra
    sql_where = (' WHERE ' + ' AND '.join(where)) if where else ''
    total = db.scalar(f'SELECT COUNT(*) FROM ad_user_cache u{sql_where}', tuple(params), 0)
    col = USER_SORTABLE.get(sort, 'sam_account_name')
    direction = 'DESC' if str(order).lower() == 'desc' else 'ASC'
    rows = db.query(
        f'SELECT u.* FROM ad_user_cache u{sql_where} ORDER BY {col} {direction}, u.id LIMIT ? OFFSET ?',
        tuple(params) + (page_size, (page - 1) * page_size))
    return rows, total


def ou_tree(domain_id: int, base_dn: str = '') -> list:
    """
    由缓存构建 OU 树（域根为虚拟根）。O(n) 建树，避免递归查询。
    """
    rows = db.query('SELECT * FROM ad_ou_cache WHERE domain_id=? ORDER BY dn', (domain_id,))
    nodes = {}
    for r in rows:
        nodes[r['dn'].lower()] = {
            'dn': r['dn'], 'name': r['name'], 'description': r['description'],
            'user_count': r['user_count'], 'children': [], 'depth': r['depth'],
            'direct_users': r['user_count'],
        }
    root = {'dn': base_dn, 'name': '域根', 'description': '', 'user_count': 0,
            'children': [], 'depth': -1, 'direct_users': 0}
    total = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=?', (domain_id,), 0)
    root['user_count'] = total
    for key, n in nodes.items():
        parent = n['dn'].split(',', 1)[1] if ',' in n['dn'] else base_dn
        p = nodes.get(parent.lower())
        if p is not None:
            p['children'].append(n)
        else:
            root['children'].append(n)

    def sort_tree(node):
        node['children'].sort(key=lambda x: x['name'] or '')
        for c in node['children']:
            sort_tree(c)
    sort_tree(root)
    # 汇总子树用户数（自底向上）
    def acc(node):
        s = node.get('direct_users', 0) or 0
        for c in node['children']:
            s += acc(c)
        node['subtree_users'] = s
        return s
    acc(root)
    return root


def list_groups(filters: dict, page: int, page_size: int, sort='name', order='asc'):
    where, params = [], []
    if filters.get('domain_id'):
        where.append('domain_id=?')
        params.append(int(filters['domain_id']))
    if filters.get('keyword'):
        like = f"%{filters['keyword']}%"
        where.append('(name LIKE ? OR sam_account_name LIKE ? OR description LIKE ?)')
        params += [like] * 3
    if filters.get('scope'):
        where.append('scope=?')
        params.append(filters['scope'])
    if filters.get('category'):
        where.append('category=?')
        params.append(filters['category'])
    sql_where = (' WHERE ' + ' AND '.join(where)) if where else ''
    total = db.scalar(f'SELECT COUNT(*) FROM ad_group_cache{sql_where}', tuple(params), 0)
    col = {'name': 'name', 'members': 'member_count', 'scope': 'scope'}.get(sort, 'name')
    direction = 'DESC' if str(order).lower() == 'desc' else 'ASC'
    rows = db.query(f'SELECT * FROM ad_group_cache{sql_where} ORDER BY {col} {direction} LIMIT ? OFFSET ?',
                    tuple(params) + (page_size, (page - 1) * page_size))
    return rows, total


def list_computers(filters: dict, page: int, page_size: int, sort='name', order='asc'):
    where, params = [], []
    if filters.get('domain_id'):
        where.append('domain_id=?')
        params.append(int(filters['domain_id']))
    if filters.get('keyword'):
        like = f"%{filters['keyword']}%"
        where.append('(name LIKE ? OR dns_host_name LIKE ? OR operating_system LIKE ? '
                     'OR description LIKE ? OR remark LIKE ?)')
        params += [like] * 5
    if filters.get('enabled') not in (None, '', 'all'):
        where.append('enabled=?')
        params.append(int(filters['enabled']))
    if filters.get('offline') in (1, '1', True):
        where.append("(last_logon='' OR last_logon IS NULL OR last_logon<datetime('now','localtime','-30 days'))")
    sql_where = (' WHERE ' + ' AND '.join(where)) if where else ''
    total = db.scalar(f'SELECT COUNT(*) FROM ad_computer_cache{sql_where}', tuple(params), 0)
    col = {'name': 'name', 'os': 'operating_system', 'logon': 'last_logon'}.get(sort, 'name')
    direction = 'DESC' if str(order).lower() == 'desc' else 'ASC'
    rows = db.query(f'SELECT * FROM ad_computer_cache{sql_where} ORDER BY {col} {direction} LIMIT ? OFFSET ?',
                    tuple(params) + (page_size, (page - 1) * page_size))
    return rows, total


def domain_counts(domain_id: int) -> dict:
    row = db.query_one(
        """SELECT COUNT(*) total, SUM(enabled) enabled, SUM(locked) locked,
                  SUM(CASE WHEN (user_account_control & 65536) <> 0 THEN 1 ELSE 0 END) never_expire
           FROM ad_user_cache WHERE domain_id=?""", (domain_id,))
    if not row:
        return {}
    return {k: int(row[k] or 0) for k in ('total', 'enabled', 'locked', 'never_expire')}


def departments(domain_id: int) -> list:
    rows = db.query("SELECT department, COUNT(*) c FROM ad_user_cache WHERE domain_id=? AND department<>'' "
                    "GROUP BY department ORDER BY c DESC", (domain_id,))
    return [{'name': r['department'], 'count': r['c']} for r in rows]


def pagination(total: int, page: int, size: int) -> dict:
    pages = max(1, (total + size - 1) // size)
    return {'total': total, 'page': page, 'size': size, 'pages': pages,
            'has_prev': page > 1, 'has_next': page < pages,
            'start': (page - 1) * size + 1 if total else 0, 'end': min(page * size, total)}
