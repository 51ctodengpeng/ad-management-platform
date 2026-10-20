# -*- coding: utf-8 -*-
"""回收站：删除目录对象前做快照，30 天内可还原；到期自动永久删除。

设计：
- 数据来源范围：AD 目录对象四类——用户(user)、用户组(group)、组织单位(ou)、计算机(computer)。
  运维账号(sys_user)、域配置等非 AD 目录对象不纳入。
- 删除方式：先 JSON 快照到 ad_recycle_bin，再物理删除 AD 对象、清缓存；回收站内为
  「软删除」标记（restored_at 为空表示仍可还原）。
- 还原冲突：检测同名/DN 冲突，提供 rename（加后缀）/ overwrite（先删现对象）/ skip 三种策略。
- 清理：默认保留 30 天，过期由调度器自动永久删除。
"""
import json

from modules import db
from modules import ad_ldap as L
from modules.applog import get_logger

log = get_logger('recycle')

ENTITY_LABEL = {'user': '用户', 'group': '用户组', 'ou': '组织单位', 'computer': '计算机'}
RETENTION_DAYS = 30


def add(entity_type: str, domain_id: int, name: str, dn: str, snapshot: dict, operator: str = '') -> int:
    """快照入回收站，返回记录 id。"""
    return db.insert(
        'INSERT INTO ad_recycle_bin(domain_id, entity_type, name, dn, snapshot, deleted_by) '
        'VALUES(?,?,?,?,?,?)',
        (domain_id, entity_type, name, dn, json.dumps(snapshot, ensure_ascii=False), operator))


def list_items(domain_id: int = None) -> list:
    where, params = "WHERE restored_at=''", []
    if domain_id:
        where += ' AND domain_id=?'
        params.append(domain_id)
    out = []
    for r in db.query(f'SELECT * FROM ad_recycle_bin {where} ORDER BY deleted_at DESC', tuple(params)):
        item = dict(r)
        item['entity_label'] = ENTITY_LABEL.get(item['entity_type'], item['entity_type'])
        item['snapshot'] = json.loads(item['snapshot'] or '{}')
        out.append(item)
    return out


def get(item_id: int):
    r = db.query_one('SELECT * FROM ad_recycle_bin WHERE id=?', (item_id,))
    if not r:
        return None
    item = dict(r)
    item['snapshot'] = json.loads(item['snapshot'] or '{}')
    return item


def purge(item_id: int) -> None:
    db.execute('DELETE FROM ad_recycle_bin WHERE id=?', (item_id,))


def purge_all() -> int:
    return db.execute("DELETE FROM ad_recycle_bin WHERE restored_at=''")


def purge_expired(days: int = RETENTION_DAYS) -> int:
    return db.execute(
        "DELETE FROM ad_recycle_bin WHERE restored_at='' AND deleted_at < datetime('now','localtime', ?)",
        (f'-{days} days',))


def mark_restored(item_id: int) -> None:
    db.execute("UPDATE ad_recycle_bin SET restored_at=datetime('now','localtime') WHERE id=?", (item_id,))


def _exists(conn, dn: str) -> bool:
    try:
        return bool(conn.search(dn, '(objectClass=*)', search_scope='BASE', attributes=['1.1'], size_limit=1))
    except Exception:
        return False


def restore(item_id: int, mode: str = 'rename', new_password: str = '') -> dict:
    """还原回收站对象。mode: rename(加后缀) / overwrite(覆盖现有) / skip(跳过)。

    返回 {ok, message, dn, conflict}。
    """
    item = get(item_id)
    if not item:
        return {'ok': False, 'message': '回收站记录不存在'}
    snap = item['snapshot']
    d = L.get_domain(item['domain_id'])
    conn = L.get_connection(d)
    if not d.enabled:
        return {'ok': False, 'message': '该域已停用，无法还原'}

    # 冲突检测
    conflict = _exists(conn, item['dn'])
    if conflict and mode == 'skip':
        return {'ok': False, 'conflict': True, 'message': f'同名对象已存在（{item["dn"]}），已跳过'}
    if conflict and mode == 'overwrite':
        try:
            conn.delete(item['dn'])
        except Exception as e:
            return {'ok': False, 'message': f'覆盖删除现有对象失败：{e}'}
        conflict = False

    try:
        if item['entity_type'] == 'user':
            return _restore_user(d, conn, item, snap, new_password, rename=conflict)
        if item['entity_type'] == 'group':
            return _restore_group(d, item, snap, rename=conflict)
        if item['entity_type'] == 'ou':
            return _restore_ou(d, item, snap, rename=conflict)
        if item['entity_type'] == 'computer':
            return _restore_computer(d, conn, item, snap, rename=conflict)
        return {'ok': False, 'message': f'不支持的类型：{item["entity_type"]}'}
    except Exception as e:
        msg = e.message if isinstance(e, L.ADError) else str(e)
        return {'ok': False, 'message': f'还原失败：{msg}'}


def _rename_suffix(name: str, max_len: int = 20) -> str:
    base = name[:max_len - 3]
    for i in range(1, 100):
        cand = f'{base}{i}'
        if len(cand) <= max_len:
            return cand
    return name


def _restore_user(d, conn, item, snap, new_password, rename: bool) -> dict:
    if not new_password:
        return {'ok': False, 'message': '还原用户需提供新密码（AD 密码无法从快照恢复）'}
    sam = snap.get('sam_account_name') or item['name']
    if rename:
        sam = _rename_suffix(sam)
    if not sam:
        return {'ok': False, 'message': '快照缺少登录名，无法还原'}
    created = L.create_user(d, {
        'sam_account_name': sam,
        'display_name': snap.get('display_name') or sam,
        'password': new_password,
        'ou_dn': snap.get('ou_dn') or d.base_dn,
        'must_change_password': True,
        'enabled': bool(snap.get('enabled', 1)),
        'mail': snap.get('mail', ''),
        'title': snap.get('title', ''),
        'department': snap.get('department', ''),
        'company': snap.get('company', ''),
        'description': snap.get('description', ''),
    })
    # 恢复组关系（尽力而为）
    restored_groups = 0
    for gdn in snap.get('groups', []) or []:
        try:
            if _exists(conn, gdn):
                L.add_group_members(d, gdn, [created['dn']], skip_health=True)
                restored_groups += 1
        except Exception:
            pass
    mark_restored(item['id'])
    return {'ok': True, 'dn': created['dn'],
            'message': f'已还原为 {sam}（恢复 {restored_groups} 个组），请用户用新密码登录'}


def _restore_group(d, item, snap, rename: bool) -> dict:
    name = snap.get('name') or item['name']
    if rename:
        name = _rename_suffix(name, 20)
    dn = L.create_group(d, {
        'name': name,
        'sam_account_name': snap.get('sam_account_name') or name,
        'ou_dn': snap.get('ou_dn') or f'CN=Users,{d.base_dn}',
        'scope': snap.get('scope') or 'Global',
        'category': snap.get('category') or 'Security',
    })
    mark_restored(item['id'])
    return {'ok': True, 'dn': dn, 'message': f'已还原组 {name}'}


def _restore_ou(d, item, snap, rename: bool) -> dict:
    name = snap.get('name') or item['name']
    if rename:
        name = _rename_suffix(name, 64)
    parent = snap.get('parent_dn') or d.base_dn
    dn = L.create_ou(d, parent, name, snap.get('description', ''))
    mark_restored(item['id'])
    return {'ok': True, 'dn': dn, 'message': f'已还原 OU {name}'}


def _restore_computer(d, conn, item, snap, rename: bool) -> dict:
    name = snap.get('name') or item['name']
    if rename:
        name = _rename_suffix(name, 15)
    dn = f'CN={name},{snap.get("ou_dn") or d.base_dn}'
    ok = conn.add(dn, object_class=['top', 'person', 'organizationalPerson', 'user', 'computer'],
                  attributes={'cn': name, 'sAMAccountName': f'{name}$',
                              'userAccountControl': 4096,
                              'dNSHostName': snap.get('dns_host_name') or f'{name.lower()}.{d.domain_name}'})
    if not ok:
        raise L.ADError(str(conn.result))
    mark_restored(item['id'])
    return {'ok': True, 'dn': dn, 'message': f'已还原计算机 {name}'}
