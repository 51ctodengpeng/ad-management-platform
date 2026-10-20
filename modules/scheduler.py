# -*- coding: utf-8 -*-
"""
定时任务调度（APScheduler）
================================
任务设计（按域隔离）：
- 任务1：每 15 分钟，每个启用域一个独立 job（sync_domain_<id>），带抖动分钟避免同时拉取。
- 任务2：每日 02:00 全量同步，逐域串行，单域失败不影响其它域。
- 任务3：每日 03:10 日志维护（归档 90 天前日志 + VACUUM）。
- 任务4：每 30 分钟刷新林信任状态（读 AD trustedDomain → 缓存）。

"按域独立"的价值：某域控宕机只让该 job 失败并标记离线，其余域照常。
新增/删除域后调用 reload_domain_jobs() 立即生效（无需重启服务）。
"""
import random

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

import config
from modules import db
from modules import ad_ldap as L
from modules.applog import get_logger

log = get_logger('scheduler')

_scheduler = None


def _sync_job(domain_id: int, kind: str = 'incr'):
    """单域同步 job 体：任何异常都吞掉，保证不影响其它 job。"""
    from modules import sync_task
    try:
        d = L.get_domain(domain_id)
        if not d.enabled:
            return
        res = sync_task.sync_domain_full(d) if kind == 'full' else sync_task.sync_domain_incremental(d)
        log.info('[定时] %s %s → %s', d.domain_name, kind, res.get('message'))
    except Exception as e:
        log.warning('[定时] 域 %s 同步失败（已隔离，不影响其它域）：%s', domain_id, e)


def _full_sync_job():
    from modules import sync_task
    log.info('[定时] 开始每日全量同步')
    for d in L.load_domains(only_enabled=True):
        _sync_job(d.id, 'full')


def _trust_job():
    from modules import ad_trust
    try:
        for res in ad_trust.refresh_all():
            if not res.get('ok'):
                log.info('[定时] 刷新信任失败：%s', res.get('message'))
    except Exception as e:
        log.warning('[定时] 刷新信任异常：%s', e)


def _log_job():
    from modules import log_service
    try:
        log_service.maintain()
    except Exception as e:
        log.warning('[定时] 日志维护失败：%s', e)


def _recycle_purge_job():
    """每日回收站清理：永久删除超过保留期的软删除记录。"""
    from modules import recycle_bin
    try:
        n = recycle_bin.purge_expired()
        if n:
            log.info('[定时] 回收站清理：永久删除 %d 条过期记录', n)
    except Exception as e:
        log.warning('[定时] 回收站清理失败：%s', e)


def _domain_status_job():
    """每 10 分钟主动探测各域在线状态，让"在线/离线"尽量接近实时。"""
    for d in L.load_domains(only_enabled=True):
        try:
            L.health(d, ttl=0)
        except Exception as e:
            log.debug('域状态探测失败 %s: %s', d.domain_name, e)


def _alert_check_job():
    """每 5 分钟评估邮箱告警策略，触发即发邮件（策略自身按频率节流）。"""
    from modules import alert_notify
    try:
        alert_notify.evaluate()
    except Exception as e:
        log.warning('[定时] 邮箱告警检查失败：%s', e)


def init_scheduler() -> BackgroundScheduler | None:
    global _scheduler
    if not config.ENABLE_SCHEDULER:
        log.warning('定时任务已通过环境变量关闭（ADM_ENABLE_SCHEDULER=0）')
        return None
    if _scheduler is not None:
        return _scheduler
    _scheduler = BackgroundScheduler(
        timezone=config.SCHEDULER_TIMEZONE,
        job_defaults={'coalesce': True, 'max_instances': 1, 'misfire_grace_time': 300,
                      'replace_existing': True},
        executors={'default': {'type': 'threadpool', 'max_workers': 4}},
    )
    _scheduler.start()
    reload_domain_jobs()
    # 每日全量 02:00
    _scheduler.add_job(_full_sync_job, CronTrigger(hour=config.SYNC_FULL_HOUR,
                                                   minute=config.SYNC_FULL_MINUTE),
                       id='full_sync_all', name='每日全量同步')
    # 日志维护 03:10
    _scheduler.add_job(_log_job, CronTrigger(hour=3, minute=10), id='log_maintain', name='日志归档与VACUUM')
    # 回收站清理 03:20（30 天过期自动永久删除）
    _scheduler.add_job(_recycle_purge_job, CronTrigger(hour=3, minute=20), id='recycle_purge',
                       name='回收站过期清理')
    # 信任刷新 每 30 分钟
    _scheduler.add_job(_trust_job, IntervalTrigger(minutes=config.TRUST_REFRESH_INTERVAL_MIN),
                       id='trust_refresh', name='林信任状态刷新',
                       next_run_time=_first_run_delay(60))
    # 域在线状态 每 2 分钟（更快自动发现掉线/恢复，避免长时间误标只读）
    _scheduler.add_job(_domain_status_job, IntervalTrigger(minutes=2), id='domain_status',
                       name='域在线状态探测', next_run_time=_first_run_delay(20))
    # 邮箱告警检查 每 5 分钟（策略内部按各自频率节流）
    _scheduler.add_job(_alert_check_job, IntervalTrigger(minutes=5), id='alert_check',
                       name='邮箱告警检查', next_run_time=_first_run_delay(45))
    log.info('调度器已启动，共 %d 个任务', len(_scheduler.get_jobs()))
    return _scheduler


def _first_run_delay(seconds: int):
    from datetime import datetime, timedelta
    return datetime.now() + timedelta(seconds=seconds)


def reload_domain_jobs() -> None:
    """为每个启用域注册独立的增量同步 job（新增域后即时生效）。"""
    if _scheduler is None:
        return
    domains = L.load_domains(only_enabled=True)
    # 先移除所有旧的域同步 job，再统一重建，避免 add_job 的 id 冲突
    for job in list(_scheduler.get_jobs()):
        if job.id.startswith('sync_domain_'):
            job.remove()
    for i, d in enumerate(domains):
        jitter = (i * 7 + random.randint(0, config.SYNC_JITTER_SECONDS)) % 60
        _scheduler.add_job(
            _sync_job, IntervalTrigger(minutes=config.SYNC_INCREMENT_INTERVAL_MIN, jitter=30),
            args=[d.id, 'incr'], id=f'sync_domain_{d.id}', name=f'增量同步·{d.domain_name}',
            next_run_time=_first_run_delay(120 + jitter))
    log.info('已注册 %d 个域的独立增量同步任务', len(domains))


def get_jobs() -> list:
    if _scheduler is None:
        return []
    out = []
    for j in _scheduler.get_jobs():
        out.append({'id': j.id, 'name': j.name,
                    'next_run': j.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if j.next_run_time else '-',
                    'trigger': str(j.trigger)})
    return out


def shutdown() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
