# -*- coding: utf-8 -*-
"""
分域同步引擎
================================
三保险机制：
1. 主动同步：AD 写成功后单条刷新缓存（upsert_* 函数，由路由调用）
2. 增量同步：每 15 分钟按 uSNChanged 拉取变更（每域独立任务）
3. 全量兜底：每日 02:00 全量比对 + 清理已删除脏数据

隔离与并发：
- 每域独立租约锁 sync:domain:<id>，手动/定时互斥，不重复拉取。
- 批量写 AD 的批次任务共用 sync:global 锁，禁止并发批量写。
- 单域失败只影响该域，事务回滚，缓存保持上一次一致状态。
- 每 SYNC_BATCH_SIZE 条提交一次，避免大事务阻塞读、避免锁库。
"""
import itertools
import random
import time
from datetime import datetime

import config
from modules import db
from modules import ad_ldap as L
from modules.applog import get_logger

log = get_logger('sync')

USER_COLS = L.PAGE_USER_CACHE_COLUMNS
_user_sql = (f'INSERT INTO ad_user_cache({",".join(USER_COLS)}, synced_at) '
             f'VALUES({",".join("?" for _ in USER_COLS)}, datetime(\'now\',\'localtime\')) '
             f'ON CONFLICT(domain_id, dn) DO UPDATE SET '
             + ', '.join(f'{c}=excluded.{c}' for c in USER_COLS if c not in ('domain_id', 'dn'))
             + ', synced_at=excluded.synced_at')
OU_COLS = ['domain_id', 'dn', 'name', 'parent_dn', 'description', 'depth', 'usn', 'when_created']
_ou_sql = (f'INSERT INTO ad_ou_cache({",".join(OU_COLS)}, synced_at) '
           f'VALUES({",".join("?" for _ in OU_COLS)}, datetime(\'now\',\'localtime\')) '
           f'ON CONFLICT(domain_id, dn) DO UPDATE SET '
           + ', '.join(f'{c}=excluded.{c}' for c in OU_COLS if c not in ('domain_id', 'dn'))
           + ', synced_at=excluded.synced_at')
GROUP_COLS = ['domain_id', 'dn', 'name', 'sam_account_name', 'scope', 'category', 'description',
              'mail', 'ou_dn', 'member_count', 'usn']
_grp_sql = (f'INSERT INTO ad_group_cache({",".join(GROUP_COLS)}, synced_at) '
            f'VALUES({",".join("?" for _ in GROUP_COLS)}, datetime(\'now\',\'localtime\')) '
            f'ON CONFLICT(domain_id, dn) DO UPDATE SET '
            + ', '.join(f'{c}=excluded.{c}' for c in GROUP_COLS if c not in ('domain_id', 'dn'))
            + ', synced_at=excluded.synced_at')


def _row_tuple(row: dict, cols: list):
    return tuple(row.get(c) for c in cols)


# ================================================================ 主动同步（写成功后单条刷新）
def upsert_user(d, row: dict) -> None:
    db.execute(_user_sql, _row_tuple(row, USER_COLS))


def refresh_user_by_dn(d, dn: str, old_sam: str = None, old_dn: str = None) -> bool:
    """
    写操作后单条回读 AD 并刷新缓存（保证与 AD 真实状态一致，
    例如 AD 侧自动置的 pwdLastSet / whenChanged 也能同步进来）。
    old_dn：重命名/移动前的 DN，用于清理旧记录，避免残留脏行。
    """
    try:
        meta = L.domain_meta(d)
        conn = L.get_connection(d)
        if not conn.search(dn, L.USER_FILTER, search_scope='BASE',
                           attributes=L.USER_ATTRS, size_limit=1):
            # AD 里已不存在（可能被重命名或删除）→ 删除缓存
            db.execute('DELETE FROM ad_user_cache WHERE domain_id=? AND dn=?', (d.id, dn))
            if old_dn and old_dn != dn:
                db.execute('DELETE FROM ad_user_cache WHERE domain_id=? AND dn=?', (d.id, old_dn))
            return False
        row = L.entry_to_user_row(conn.entries[0], d, meta.get('max_pwd_age_days'))
        upsert_user(d, row)
        # 清理旧 DN（重命名/移动后），以及同 sam 账号指向其它 DN 的历史脏行
        if old_dn and old_dn != dn:
            db.execute('DELETE FROM ad_user_cache WHERE domain_id=? AND dn=?', (d.id, old_dn))
        db.execute('DELETE FROM ad_user_cache WHERE domain_id=? AND sam_account_name=? AND dn<>?',
                   (d.id, row['sam_account_name'], dn))
        _recount_ou(d.id)
        return True
    except L.ADError as e:
        log.warning('回读用户缓存失败 %s/%s: %s', d.domain_name, dn, e.message)
        return False


def upsert_user_partial(d, dn: str, patch: dict) -> None:
    """已知部分字段时（AD 已成功，避免再查一次 AD）直接更新缓存。"""
    if not patch:
        return
    sets = ', '.join(f'{k}=?' for k in patch)
    db.execute(f"UPDATE ad_user_cache SET {sets}, synced_at=datetime('now','localtime') "
               f'WHERE domain_id=? AND dn=?', tuple(patch.values()) + (d.id, dn))


def rename_user_cache(d, old_dn: str, new_dn: str, new_name: str = None) -> None:
    patch = {'dn': new_dn}
    if new_name:
        patch['cn'] = new_name
        patch['display_name'] = new_name
    sets = ', '.join(f'{k}=?' for k in patch)
    try:
        db.execute(f'UPDATE ad_user_cache SET {sets} WHERE domain_id=? AND dn=?',
                   tuple(patch.values()) + (d.id, old_dn))
    except Exception:
        # 目标 DN 已存在（重命名冲突），删掉旧行让同步补齐
        db.execute('DELETE FROM ad_user_cache WHERE domain_id=? AND dn=?', (d.id, old_dn))


def delete_user_cache(d, dn: str) -> None:
    db.execute('DELETE FROM ad_user_cache WHERE domain_id=? AND dn=?', (d.id, dn))
    _recount_ou(d.id)


def upsert_ou(d, row: dict) -> None:
    db.execute(_ou_sql, _row_tuple(row, OU_COLS))


def delete_ou_cache(d, dn: str) -> None:
    db.execute("DELETE FROM ad_ou_cache WHERE domain_id=? AND (dn=? OR dn LIKE ? ESCAPE '\\')",
               (d.id, dn, db.dn_like(dn)))


def upsert_group(d, row: dict) -> None:
    db.execute(_grp_sql, _row_tuple(row, GROUP_COLS))


def upsert_computer(d, row: dict) -> None:
    with db.tx(immediate=True) as c:
        _upsert_computer_conn(c, d.id, row)


def delete_computer_cache(d, dn: str) -> None:
    db.execute('DELETE FROM ad_computer_cache WHERE domain_id=? AND dn=?', (d.id, dn))


def _recount_ou(domain_id: int) -> None:
    """维护 OU 直属用户数（用户表变更后调用，单条 SQL，开销可控）。"""
    try:
        db.execute(
            "UPDATE ad_ou_cache SET user_count=(SELECT COUNT(*) FROM ad_user_cache u "
            "WHERE u.domain_id=ad_ou_cache.domain_id AND u.ou_dn=ad_ou_cache.dn) WHERE domain_id=?",
            (domain_id,))
    except Exception as e:
        log.debug('重算 OU 用户数失败: %s', e)


# ================================================================ 增量同步
def _max_usn_of(entries) -> int:
    best = 0
    for e in entries:
        try:
            best = max(best, int(e['uSNChanged'].value))
        except Exception:
            pass
    return best


def _already_done(d) -> bool:
    """预留：判断本域近期是否已有同步完成，用于调度器跳过重复任务。"""
    row = db.query_one('SELECT last_sync_at FROM ad_domain_conf WHERE id=?', (d.id,))
    return bool(row and row['last_sync_at'])


def sync_domain_incremental(d, force: bool = False) -> dict:
    """单域增量同步：uSNChanged 水位线 → 拉取变更 → upsert（分批事务）。"""
    result = {'domain_id': d.id, 'domain': d.domain_name, 'type': 'incr', 'ok': False,
              'users': 0, 'ous': 0, 'deleted': 0, 'message': '', 'elapsed': 0}
    t0 = time.time()
    try:
        with db.sync_lock(f'sync:domain:{d.id}', ttl=900):
            meta = L.domain_meta(d)
            current, _, _ = _read_usn_watermark(d.id)
            max_pwd_age = meta.get('max_pwd_age_days')
            # 首次跑增量（水位线为 0）→ 退化为全量，避免从 0 开始拉全部历史
            if current <= 0:
                return sync_domain_full(d, _lock_held=True)
            conn = L.get_connection(d)
            new_max = 0
            # 1) 用户增量
            users = L.list_users_by_usn(d, current, max_pwd_age)
            new_max = max(new_max, max([u['usn'] for u in users], default=0))
            for i, batch in enumerate(_chunks(users, config.SYNC_BATCH_SIZE)):
                with db.tx(immediate=True) as c:
                    for u in batch:
                        c.execute(_user_sql, _row_tuple(u, USER_COLS))
                result['users'] += len(batch)
            # 2) OU 增量
            ous = L.list_ous_by_usn(d, current)
            new_max = max(new_max, max([o['usn'] for o in ous], default=0))
            for batch in _chunks(ous, config.SYNC_BATCH_SIZE):
                with db.tx(immediate=True) as c:
                    for o in batch:
                        c.execute(_ou_sql, _row_tuple(o, OU_COLS))
                result['ous'] += len(batch)
            # 3) 组/计算机：仅做存在性与数量级校验（变更量小，直接全量 upsert 成本可控）
            groups = L.list_groups(d)
            for batch in _chunks(groups, config.SYNC_BATCH_SIZE):
                with db.tx(immediate=True) as c:
                    for g in batch:
                        c.execute(_grp_sql, _row_tuple(g, GROUP_COLS))
            computers = L.list_computers(d)
            with db.tx(immediate=True) as c:
                for cp in computers:
                    _upsert_computer_conn(c, d.id, cp)
            # 4) 删除检测：uSNChanged 无法反映删除，用 OU/组/计算机集合比对（用户按 DN 集合轻量比对）
            existing_dns = L.get_user_dn_list(d)
            cached = {r['dn'] for r in db.query('SELECT dn FROM ad_user_cache WHERE domain_id=?', (d.id,))}
            gone = cached - existing_dns
            if gone:
                with db.tx(immediate=True) as c:
                    for dn in gone:
                        c.execute('DELETE FROM ad_user_cache WHERE domain_id=? AND dn=?', (d.id, dn))
                result['deleted'] = len(gone)
            _reconcile_groups_computers(d.id, {g['dn'] for g in groups}, {c['dn'] for c in computers})
            # 5) 推进水位线（取本次最大 USN，保证下次从变更之后开始）
            watermark = max(new_max, current)
            with db.tx(immediate=True) as c:
                c.execute("UPDATE ad_domain_conf SET max_usn=?, last_sync_at=datetime('now','localtime'), "
                          "last_sync_type='incr', last_sync_msg=?, status='online' WHERE id=?",
                          (watermark, f'增量同步：用户 {result["users"]}、OU {result["ous"]}、'
                                      f'清理 {result["deleted"]}', d.id))
            _recount_ou(d.id)
            result['ok'] = True
            result['message'] = (f'增量同步完成：变更用户 {result["users"]} 个、OU {result["ous"]} 个，'
                                 f'清理已删除用户 {result["deleted"]} 个')
            L.mark_health(d, True, '增量同步正常')
    except db.LockBusy:
        result['message'] = '该域正在同步中，已跳过本次'
        result['skip'] = True
        return result
    except L.ADError as e:
        result['message'] = e.message
        if isinstance(e, L.ADUnavailable):
            L.mark_health(d, False, e.message)
        _record_sync_error(d.id, 'incr', e.message)
    except Exception as e:                                        # pragma: no cover
        log.exception('增量同步异常 %s', d.domain_name)
        result['message'] = f'增量同步异常：{e}'
        _record_sync_error(d.id, 'incr', str(e))
    finally:
        result['elapsed'] = round(time.time() - t0, 2)
    return result


# ================================================================ 全量同步
def _upsert_computer_conn(c, domain_id: int, row: dict) -> None:
    c.execute(
        'INSERT INTO ad_computer_cache(domain_id, dn, name, dns_host_name, operating_system, os_version, '
        'description, ou_dn, enabled, last_logon, when_created, usn, synced_at) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,datetime(\'now\',\'localtime\')) '
        'ON CONFLICT(domain_id, dn) DO UPDATE SET name=excluded.name, dns_host_name=excluded.dns_host_name, '
        'operating_system=excluded.operating_system, os_version=excluded.os_version, '
        'description=excluded.description, ou_dn=excluded.ou_dn, enabled=excluded.enabled, '
        'last_logon=excluded.last_logon, when_created=excluded.when_created, usn=excluded.usn, '
        'synced_at=excluded.synced_at',
        (domain_id, row['dn'], row['name'], row['dns_host_name'], row['operating_system'],
         row['os_version'], row['description'], row['ou_dn'], row['enabled'],
         row['last_logon'], row['when_created'], row['usn']))


def _reconcile_groups_computers(domain_id: int, group_dns: set, computer_dns: set) -> int:
    removed = 0
    for table, keep in (('ad_group_cache', group_dns), ('ad_computer_cache', computer_dns)):
        cached = {r['dn'] for r in db.query(f'SELECT dn FROM {table} WHERE domain_id=?', (domain_id,))}
        gone = cached - keep
        if gone:
            with db.tx(immediate=True) as c:
                for dn in gone:
                    c.execute(f'DELETE FROM {table} WHERE domain_id=? AND dn=?', (domain_id, dn))
            removed += len(gone)
    return removed


def _read_usn_watermark(domain_id: int):
    row = db.query_one('SELECT max_usn, last_sync_at, last_sync_type FROM ad_domain_conf WHERE id=?', (domain_id,))
    if not row:
        return 0, None, None
    return int(row['max_usn'] or 0), row['last_sync_at'], row['last_sync_type']


def sync_domain_full(d, _lock_held: bool = False) -> dict:
    """单域全量同步：拉全量 → upsert → 比对清理脏数据 → 重置水位线。"""
    result = {'domain_id': d.id, 'domain': d.domain_name, 'type': 'full', 'ok': False,
              'users': 0, 'ous': 0, 'groups': 0, 'computers': 0, 'deleted': 0,
              'message': '', 'elapsed': 0}
    t0 = time.time()

    def _run():
        meta = L.domain_meta(d)
        max_pwd_age = meta.get('max_pwd_age_days')
        if meta.get('base_dn'):
            db.execute('UPDATE ad_domain_conf SET base_dn=?, forest_name=?, domain_sid=?, domain_mode=? WHERE id=?',
                       (meta['base_dn'], meta.get('forest'), meta.get('domain_sid'),
                        meta.get('domain_mode'), d.id))
        # 用户
        users = L.list_users(d, max_pwd_age)
        for batch in _chunks(users, config.SYNC_BATCH_SIZE):
            with db.tx(immediate=True) as c:
                for u in batch:
                    c.execute(_user_sql, _row_tuple(u, USER_COLS))
            result['users'] += len(batch)
        # OU
        ous = L.list_ous(d)
        for batch in _chunks(ous, config.SYNC_BATCH_SIZE):
            with db.tx(immediate=True) as c:
                for o in batch:
                    c.execute(_ou_sql, _row_tuple(o, OU_COLS))
            result['ous'] += len(batch)
        # 组
        groups = L.list_groups(d)
        for batch in _chunks(groups, config.SYNC_BATCH_SIZE):
            with db.tx(immediate=True) as c:
                for g in batch:
                    c.execute(_grp_sql, _row_tuple(g, GROUP_COLS))
            result['groups'] += len(batch)
        # 计算机
        computers = L.list_computers(d)
        with db.tx(immediate=True) as c:
            for cp in computers:
                _upsert_computer_conn(c, d.id, cp)
        result['computers'] = len(computers)
        # 清理脏数据
        removed = 0
        keep_users = {u['dn'] for u in users}
        keep_ous = {o['dn'] for o in ous}
        for table, keep in (('ad_user_cache', keep_users), ('ad_ou_cache', keep_ous)):
            cached = {r['dn'] for r in db.query(f'SELECT dn FROM {table} WHERE domain_id=?', (d.id,))}
            gone = cached - keep
            if gone:
                with db.tx(immediate=True) as c:
                    for dn in gone:
                        c.execute(f'DELETE FROM {table} WHERE domain_id=? AND dn=?', (d.id, dn))
                removed += len(gone)
        removed += _reconcile_groups_computers(d.id, {g['dn'] for g in groups},
                                               {x['dn'] for x in computers})
        result['deleted'] = removed
        watermark = max([u['usn'] for u in users] + [0])
        with db.tx(immediate=True) as c:
            c.execute("UPDATE ad_domain_conf SET max_usn=?, last_sync_at=datetime('now','localtime'), "
                      "last_sync_type='full', last_sync_msg=?, status='online' WHERE id=?",
                      (watermark, f'全量同步：用户 {result["users"]}、OU {result["ous"]}、'
                                  f'组 {result["groups"]}、计算机 {result["computers"]}', d.id))
        _recount_ou(d.id)
        result['ok'] = True
        result['message'] = (f'全量同步完成：用户 {result["users"]}、OU {result["ous"]}、组 {result["groups"]}、'
                             f'计算机 {result["computers"]}，清理脏数据 {removed} 条')
        L.mark_health(d, True, '全量同步正常')

    try:
        if _lock_held:
            _run()
        else:
            with db.sync_lock(f'sync:domain:{d.id}', ttl=3600):
                _run()
    except db.LockBusy:
        result['message'] = '该域正在同步中，已跳过本次'
        result['skip'] = True
    except L.ADError as e:
        result['message'] = e.message
        if isinstance(e, L.ADUnavailable):
            L.mark_health(d, False, e.message)
        _record_sync_error(d.id, 'full', e.message)
    except Exception as e:                                        # pragma: no cover
        log.exception('全量同步异常 %s', d.domain_name)
        result['message'] = f'全量同步异常：{e}'
        _record_sync_error(d.id, 'full', str(e))
    finally:
        result['elapsed'] = round(time.time() - t0, 2)
    return result


def _record_sync_error(domain_id: int, kind: str, msg: str) -> None:
    try:
        db.execute("UPDATE ad_domain_conf SET last_sync_msg=? WHERE id=?", (f'{kind} 同步失败：{msg}'[:900], domain_id))
    except Exception:
        pass


def _chunks(seq, n):
    it = iter(seq)
    while True:
        batch = list(itertools.islice(it, n))
        if not batch:
            return
        yield batch


# ================================================================ 多域批量
def sync_one(domain_id: int, kind: str = 'incr', operator: str = 'scheduler', owner: str = None) -> dict:
    """对外统一入口：单域同步（自动记录操作日志）。"""
    from modules import log_service
    t0 = time.time()
    operator = operator or owner or 'scheduler'
    try:
        d = L.get_domain(domain_id)
    except L.ADError as e:
        return {'ok': False, 'domain_id': domain_id, 'domain': str(domain_id), 'message': e.message}
    res = sync_domain_full(d) if kind == 'full' else sync_domain_incremental(d)
    log_service.write('sync', f'{kind}_sync', target=d.label,
                      result='success' if res.get('ok') else 'failed',
                      message=res.get('message', ''), operator=operator, domain_id=d.id,
                      domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
    res.setdefault('domain', d.domain_name)
    return res


def sync_all(kind: str = 'incr', operator: str = 'scheduler') -> list:
    """
    全部域同步：逐域串行执行，单域失败不影响其它域（故障隔离）。
    域间隔随机抖动，避免同时压满网络。
    """
    results = []
    domains = L.load_domains(only_enabled=True)
    for i, d in enumerate(domains):
        try:
            res = sync_domain_full(d) if kind == 'full' else sync_domain_incremental(d)
        except Exception as e:                                     # pragma: no cover
            res = {'domain_id': d.id, 'domain': d.domain_name, 'ok': False, 'message': str(e)}
        results.append(res)
        log.info('同步域 %s → %s: %s', d.domain_name, res.get('ok'), res.get('message'))
        if i < len(domains) - 1 and kind != 'full':
            time.sleep(random.uniform(1, config.SYNC_JITTER_SECONDS / 10.0))
    return results


def bootstrap_missing(operator: str = 'system') -> list:
    """首次录入域后：立刻做一次全量，保证列表页有数据。"""
    out = []
    for d in L.load_domains(only_enabled=True):
        cnt = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=?', (d.id,), 0)
        if cnt == 0:
            out.append(sync_domain_full(d))
    return out


def status_summary() -> dict:
    """同步状态汇总（仪表盘用）。"""
    rows = db.query('SELECT id, name, domain_name, status, status_msg, last_sync_at, last_sync_type, '
                    'last_sync_msg, max_usn FROM ad_domain_conf ORDER BY id')
    out = []
    for r in rows:
        out.append(dict(r) | {
            'user_count': db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=?', (r['id'],), 0),
        })
    return {'domains': out, 'now': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
