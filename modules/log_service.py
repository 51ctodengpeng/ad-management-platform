# -*- coding: utf-8 -*-
"""
日志服务
================================
1. 操作日志落库（每条标记 domain_id / domain_name，便于按域审计）。
2. 自动维护：保留 90 天，过期日志归档到 archive/ 目录（CSV），再 VACUUM 回收空间。
3. 登录日志同样走这里（module=auth）。
"""
import csv
import gzip
import os
import time

import config
from modules import db
from modules.applog import get_logger

log = get_logger('log')

MODULE_NAMES = {
    'auth': '登录认证', 'domain': '域管理', 'trust': '林间信任',
    'user': '用户管理', 'ou': '部门OU', 'group': '用户组',
    'computer': '计算机', 'sync': '数据同步', 'system': '系统设置',
}


def detect_client_type(ua: str) -> str:
    """从 User-Agent 解析客户端类型（浏览器/脚本工具）。"""
    ua = (ua or '').lower()
    if 'edg/' in ua:
        return 'Edge'
    if 'opr/' in ua or 'opera' in ua:
        return 'Opera'
    if 'chrome/' in ua:
        return 'Chrome'
    if 'firefox/' in ua:
        return 'Firefox'
    if 'safari/' in ua:
        return 'Safari'
    if 'msie ' in ua or 'trident/' in ua:
        return 'IE'
    if 'python' in ua or 'curl' in ua or 'wget' in ua or 'postman' in ua or 'powershell' in ua:
        return '脚本/工具'
    return '其他'


def write(module: str, action: str, target: str = '', detail: str = '', result: str = 'success',
          message: str = '', operator: str = '', ip: str = '', domain_id=None,
          domain_name: str = '', duration_ms: int = None,
          client_type: str = '') -> int:
    """写一条操作日志。日志失败绝不影响主流程。"""
    try:
        if not domain_name and domain_id:
            row = db.query_one('SELECT name, domain_name FROM ad_domain_conf WHERE id=?', (domain_id,))
            if row:
                domain_name = f"{row['name']}({row['domain_name']})"
        return db.insert(
            'INSERT INTO ad_operation_log(domain_id, domain_name, module, action, target, detail, '
            'result, message, operator, ip, client_type, duration_ms) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
            (domain_id, domain_name, module, action, target or '', (detail or '')[:4000],
             result, (message or '')[:4000], operator or '', ip or '',
             (client_type or '')[:40], duration_ms),
        )
    except Exception as e:                                   # pragma: no cover
        log.warning('写操作日志失败: %s', e)
        return 0


def archive_dir() -> str:
    d = os.path.join(config.WORK_DIR, 'logs', 'archive')
    os.makedirs(d, exist_ok=True)
    return d


def maintain(retention_days: int = None) -> dict:
    """
    日志维护：归档 + 清理 + VACUUM。
    - 过期数据先导出 gzip csv 到 logs/archive，保证可追溯，再删除。
    - VACUUM 需要独占，放在凌晨任务里执行，执行前尽量等待。
    """
    retention_days = retention_days or config.LOG_RETENTION_DAYS
    cutoff = time.strftime('%Y-%m-%d %H:%M:%S',
                           time.localtime(time.time() - retention_days * 86400))
    row = db.query_one('SELECT COUNT(*) c, MIN(created_at) a, MAX(created_at) b FROM ad_operation_log WHERE created_at < ?', (cutoff,))
    total = row['c'] if row else 0
    archived = 0
    result = {'deleted': 0, 'archived_file': '', 'vacuum': False, 'retention_days': retention_days}
    if total:
        path = os.path.join(archive_dir(), f'operation_log_{time.strftime("%Y%m%d_%H%M%S")}.csv.gz')
        rows = db.query('SELECT * FROM ad_operation_log WHERE created_at < ? ORDER BY id', (cutoff,))
        with gzip.open(path, 'wt', encoding='utf-8-sig', newline='') as f:
            w = csv.writer(f)
            if rows:
                w.writerow(rows[0].keys())
                for r in rows:
                    w.writerow([r[k] for k in r.keys()])
        archived = len(rows)
        result['archived_file'] = path
    with db.tx(immediate=True) as conn:
        cur = conn.execute('DELETE FROM ad_operation_log WHERE created_at < ?', (cutoff,))
        result['deleted'] = cur.rowcount
    # 任务日志同样保留 30 天
    with db.tx(immediate=True) as conn:
        conn.execute("DELETE FROM task_queue WHERE created_at < datetime('now','localtime','-30 days')")
    try:
        db.get_conn().execute('PRAGMA wal_checkpoint(TRUNCATE)')
        db.get_conn().execute('VACUUM')
        result['vacuum'] = True
    except Exception as e:
        log.warning('VACUUM 失败（可能有活动连接，下次重试）: %s', e)
    write('system', 'log_maintain', target='operation_log', result='success',
          detail=f'归档 {archived} 条，删除 {result["deleted"]} 条，保留 {retention_days} 天',
          operator='system')
    log.info('日志维护完成: %s', result)
    return result


def clear_all(archive: bool = True) -> dict:
    """手动「全部清理」：清空操作日志表（可选先归档全部日志），再 VACUUM 回收空间。"""
    total = db.scalar('SELECT COUNT(*) FROM ad_operation_log', (), 0)
    result = {'deleted': 0, 'archived_file': '', 'vacuum': False, 'total': total}
    if total and archive:
        path = os.path.join(archive_dir(), f'operation_log_all_{time.strftime("%Y%m%d_%H%M%S")}.csv.gz')
        rows = db.query('SELECT * FROM ad_operation_log ORDER BY id')
        with gzip.open(path, 'wt', encoding='utf-8-sig', newline='') as f:
            w = csv.writer(f)
            if rows:
                w.writerow(rows[0].keys())
                for r in rows:
                    w.writerow([r[k] for k in r.keys()])
        result['archived_file'] = path
    with db.tx(immediate=True) as conn:
        cur = conn.execute('DELETE FROM ad_operation_log')
        result['deleted'] = cur.rowcount
    try:
        db.get_conn().execute('PRAGMA wal_checkpoint(TRUNCATE)')
        db.get_conn().execute('VACUUM')
        result['vacuum'] = True
    except Exception as e:
        log.warning('VACUUM 失败（可能有活动连接，下次重试）: %s', e)
    write('system', 'log_clear_all', target='operation_log', result='success',
          detail=f'手动全部清理，删除 {result["deleted"]} 条', operator='system')
    log.info('日志全部清理完成: %s', result)
    return result


def search(filters: dict, page: int = 1, page_size: int = 20):
    where, params = [], []
    if filters.get('domain_id'):
        where.append('domain_id = ?')
        params.append(int(filters['domain_id']))
    if filters.get('module'):
        where.append('module = ?')
        params.append(filters['module'])
    if filters.get('result'):
        where.append('result = ?')
        params.append(filters['result'])
    if filters.get('operator'):
        where.append('operator LIKE ?')
        params.append(f"%{filters['operator']}%")
    if filters.get('keyword'):
        where.append('(target LIKE ? OR detail LIKE ? OR message LIKE ? OR action LIKE ?)')
        kw = f"%{filters['keyword']}%"
        params += [kw, kw, kw, kw]
    if filters.get('date_from'):
        where.append('created_at >= ?')
        params.append(filters['date_from'] + ' 00:00:00')
    if filters.get('date_to'):
        where.append('created_at <= ?')
        params.append(filters['date_to'] + ' 23:59:59')
    sql_where = (' WHERE ' + ' AND '.join(where)) if where else ''
    total = db.scalar(f'SELECT COUNT(*) FROM ad_operation_log{sql_where}', tuple(params), 0)
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    rows = db.query(
        f'SELECT * FROM ad_operation_log{sql_where} ORDER BY id DESC LIMIT ? OFFSET ?',
        tuple(params) + (page_size, (page - 1) * page_size))
    return rows, total


def export_rows(filters: dict, limit: int = config.EXPORT_ROW_LIMIT):
    rows, _ = search(filters, page=1, page_size=limit)
    return rows
