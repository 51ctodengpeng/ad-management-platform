# -*- coding: utf-8 -*-
"""
后台任务队列（单并发执行）
================================
规范要求：批量任务排队执行，禁止多并发批量写 AD。
实现：一个常驻后台 worker 线程，按 id 顺序取 pending 任务；执行期持有全局租约锁。
- 任务类型：sync_domain / sync_all / trust_refresh
- 批量 AD 操作（批量禁用/移动/删除/加组）由 routes 层在单请求内串行完成，
  并同样先抢 global 锁，保证与同步任务互斥。

这样即使多个运维同时点击"批量同步 / 批量删除"，也不会同时向 AD 发起写风暴。
"""
import json
import queue
import threading
import time
import uuid

from modules import db
from modules.applog import get_logger

log = get_logger('queue')

_global = {'worker': None, 'q': queue.Queue(), 'running': False, 'current': None, 'lock': threading.Lock()}
BATCH_LOCK = 'batch:write'


def ensure_worker() -> None:
    if _global['worker'] and _global['worker'].is_alive():
        return
    with _global['lock']:
        if _global['worker'] and _global['worker'].is_alive():
            return
        t = threading.Thread(target=_loop, name='task-worker', daemon=True)
        t.start()
        _global['worker'] = t
        log.info('后台任务 worker 已启动')


def enqueue(task_type: str, domain_id: int = None, payload: dict = None, operator: str = '') -> int:
    task_id = db.insert(
        'INSERT INTO task_queue(task_type, domain_id, payload, status, operator) VALUES(?,?,?,?,?)',
        (task_type, domain_id, json.dumps(payload or {}, ensure_ascii=False), 'pending', operator))
    ensure_worker()
    _global['q'].put(task_id)
    return task_id


def _loop() -> None:
    while True:
        try:
            task_id = _global['q'].get(timeout=5)
        except queue.Empty:
            # 兜底：把库里 pending 但没进内存队列的任务捞回来（进程重启场景）
            try:
                for tid in db.pending_task_ids(20):
                    _global['q'].put(tid)
            except Exception:
                pass
            continue
        try:
            _run_task(task_id)
        except Exception:                                          # pragma: no cover
            log.exception('任务执行异常 id=%s', task_id)
        finally:
            _global['q'].task_done()


def _run_task(task_id: int) -> None:
    row = db.query_one('SELECT * FROM task_queue WHERE id=?', (task_id,))
    if not row or row['status'] != 'pending':
        return
    db.execute("UPDATE task_queue SET status='running', started_at=datetime('now','localtime') WHERE id=?",
               (task_id,))
    _global['current'] = {'id': task_id, 'type': row['task_type'], 'started': time.time()}
    payload = {}
    try:
        payload = json.loads(row['payload'] or '{}')
    except Exception:
        pass
    ok, msg = False, ''
    try:
        from modules import sync_task, ad_trust
        # 所有任务串行执行，避免写入冲突
        with db.sync_lock('task:global', ttl=3600 * 3, wait=600):
            if row['task_type'] == 'sync_domain':
                res = sync_task.sync_one(row['domain_id'], payload.get('kind', 'incr'), owner=row['operator'] or 'scheduler')
                ok = bool(res.get('ok'))
                msg = res.get('message', '')
            elif row['task_type'] == 'sync_all':
                results = sync_task.sync_all(payload.get('kind', 'incr'), owner=row['operator'] or 'scheduler')
                ok = all(r.get('ok') or r.get('skip') for r in results)
                succ = sum(1 for r in results if r.get('ok'))
                msg = f'共 {len(results)} 个域，成功 {succ} 个' + (
                    '；失败：' + '；'.join(f"{r.get('domain')}: {r.get('message')}" for r in results
                                        if not r.get('ok')) if any(not r.get('ok') for r in results) else '')
            elif row['task_type'] == 'trust_refresh':
                res = ad_trust.refresh_trusts(row['domain_id']) if row['domain_id'] else \
                    {'ok': True, 'message': f'已刷新 {len(ad_trust.refresh_all())} 个域'}
                ok = bool(res.get('ok'))
                msg = res.get('message', '')
            else:
                msg = f'未知任务类型 {row["task_type"]}'
        db.execute("UPDATE task_queue SET status=?, message=?, finished_at=datetime('now','localtime') WHERE id=?",
                   ('success' if ok else 'failed', msg[:2000], task_id))
    except Exception as e:
        db.execute("UPDATE task_queue SET status='failed', message=?, finished_at=datetime('now','localtime') "
                   'WHERE id=?', (f'{e}'[:2000], task_id))
    finally:
        _global['current'] = None


def acquire_batch_lock(timeout: float = 300):
    """同步/批量互斥锁。返回租约对象，调用方负责 release；获取失败抛 LockBusy。"""
    return db.sync_lock(BATCH_LOCK, ttl=1800, wait=timeout)


def status() -> dict:
    rows = db.query('SELECT * FROM task_queue ORDER BY id DESC LIMIT 20')
    pending = db.scalar("SELECT COUNT(*) FROM task_queue WHERE status IN ('pending','running')", (), 0)
    return {
        'running': _global['running'] or bool(_global['current']),
        'current': _global['current'],
        'pending': pending,
        'recent': [dict(r) for r in rows],
    }
