# -*- coding: utf-8 -*-
"""仪表盘：多域总览（全部读 SQLite 缓存）"""
from datetime import datetime, timedelta

from flask import Blueprint, render_template

from modules import db
from modules import ad_ldap as L
from modules import sync_task, task_queue
from routes.common import login_required

bp = Blueprint('dashboard', __name__)


def build_overview() -> dict:
    """汇总统计：一次 SQL 聚合，避免 N 次查询。按域过滤在 SQL 内完成。"""
    domains = L.load_domains()
    per_domain = []
    agg = {'total': 0, 'enabled': 0, 'disabled': 0, 'locked': 0, 'pwd_expired': 0,
           'never_logon': 0, 'idle_90': 0}
    soon = (datetime.now() + timedelta(days=14)).strftime('%Y-%m-%d %H:%M:%S')
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    idle = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
    for d in domains:
        row = db.query_one(
            """SELECT COUNT(*) total,
                      SUM(enabled) enabled,
                      SUM(CASE WHEN enabled=0 THEN 1 ELSE 0 END) disabled,
                      SUM(locked) locked,
                      SUM(CASE WHEN pwd_expires_at<>'' AND pwd_expires_at<=? THEN 1 ELSE 0 END) pwd_expired,
                      SUM(CASE WHEN last_logon='' OR last_logon IS NULL THEN 1 ELSE 0 END) never_logon,
                      SUM(CASE WHEN last_logon<>'' AND last_logon<? THEN 1 ELSE 0 END) idle_90,
                      SUM(CASE WHEN pwd_expires_at<>'' AND pwd_expires_at>? AND pwd_expires_at<=? THEN 1 ELSE 0 END) pwd_soon
               FROM ad_user_cache WHERE domain_id=?""",
            (now, idle, now, soon, d.id))
        stat = {k: int(row[k] or 0) for k in ('total', 'enabled', 'disabled', 'locked', 'pwd_expired',
                                              'never_logon', 'idle_90', 'pwd_soon')} if row else {}
        stat.update({
            'id': d.id, 'name': d.name, 'domain_name': d.domain_name, 'status': d.status,
            'status_msg': d.status_msg, 'is_debug': d.is_debug, 'enabled_flag': d.enabled,
            'ou_count': db.scalar('SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=?', (d.id,), 0),
            'group_count': db.scalar('SELECT COUNT(*) FROM ad_group_cache WHERE domain_id=?', (d.id,), 0),
            'computer_count': db.scalar('SELECT COUNT(*) FROM ad_computer_cache WHERE domain_id=?', (d.id,), 0),
            'trust_count': db.scalar('SELECT COUNT(*) FROM ad_trust_cache WHERE domain_id=?', (d.id,), 0),
        })
        last = db.query_one('SELECT last_sync_at, last_sync_type, last_sync_msg FROM ad_domain_conf WHERE id=?',
                            (d.id,))
        stat['last_sync_at'] = last['last_sync_at'] if last else ''
        stat['last_sync_type'] = last['last_sync_type'] if last else ''
        per_domain.append(stat)
        for k in ('total', 'enabled', 'disabled', 'locked', 'pwd_expired', 'never_logon', 'idle_90'):
            agg[k] += stat.get(k, 0)

    # 今日操作统计（按域 + 按模块）
    today = datetime.now().strftime('%Y-%m-%d')
    op_total = db.scalar("SELECT COUNT(*) FROM ad_operation_log WHERE created_at>=?", (today + ' 00:00:00',), 0)
    op_failed = db.scalar("SELECT COUNT(*) FROM ad_operation_log WHERE created_at>=? AND result='failed'",
                          (today + ' 00:00:00',), 0)
    op_by_domain = db.query(
        "SELECT domain_name, COUNT(*) c FROM ad_operation_log WHERE created_at>=? GROUP BY domain_name "
        "ORDER BY c DESC", (today + ' 00:00:00',))
    op_by_module = db.query(
        "SELECT module, COUNT(*) c FROM ad_operation_log WHERE created_at>=? GROUP BY module ORDER BY c DESC",
        (today + ' 00:00:00',))

    # 最近异常（离线域 / 同步失败）；key 供前端「清除」记忆（当天不再显示）
    alerts = []
    for s in per_domain:
        if not s['enabled_flag']:
            alerts.append({'key': f'disabled:{s["id"]}', 'level': 'secondary',
                           'text': f'{s["name"]} 已停用（只读）'})
        elif s['status'] == 'offline':
            alerts.append({'key': f'offline:{s["id"]}', 'level': 'danger',
                           'text': f'{s["name"]}（{s["domain_name"]}）离线：{s["status_msg"]}'})
        elif s['status'] == 'unknown':
            alerts.append({'key': f'unknown:{s["id"]}', 'level': 'warning',
                           'text': f'{s["name"]} 尚未检测连通状态'})
    if op_failed:
        alerts.append({'key': f'opfailed:{today}', 'level': 'warning',
                       'text': f'今日有 {op_failed} 次操作失败，请查看日志审计'})

    total_trust = db.scalar('SELECT COUNT(*) FROM ad_trust_cache', (), 0) or 0
    from modules import ad_trust
    tsum = ad_trust.trust_summary()
    return {
        'per_domain': per_domain, 'agg': agg, 'domains': domains,
        'op_total': op_total, 'op_failed': op_failed,
        'op_by_domain': [dict(r) for r in op_by_domain],
        'op_by_module': [dict(r) for r in op_by_module],
        'alerts': alerts, 'trust_total': total_trust, 'trust_verified': tsum['verified'],
        'online': sum(1 for s in per_domain if s['status'] == 'online' and s['enabled_flag']),
        'offline': sum(1 for s in per_domain if s['status'] == 'offline' and s['enabled_flag']),
        'task': task_queue.status(),
        'now': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


@bp.route('/')
@bp.route('/dashboard')
@login_required
def index():
    from modules import sync_task as st
    ov = build_overview()
    # 最近 7 天账号变动趋势（按创建时间统计，读缓存）
    trend = []
    for i in range(6, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime('%m-%d')
        cnt = db.scalar("SELECT COUNT(*) FROM ad_user_cache WHERE date(when_created)=date('now','localtime',?)",
                        (f'-{i} day',), 0)
        trend.append({'day': day, 'count': cnt})
    return render_template('dashboard.html', ov=ov, trend=trend,
                           sync_status=st.status_summary())
