# -*- coding: utf-8 -*-
"""多域管理：配置 CRUD、连通性测试、单域/批量同步、状态刷新"""
import time

from flask import Blueprint, render_template, request

import config
from modules import db
from modules import ad_ldap as L
from modules import domain_service, sync_task, task_queue, ad_trust
from modules.scheduler import reload_domain_jobs
from routes.common import (login_required, admin_required, ok, fail, api_error, log_op,
                           operator_name, require_confirm, int_arg, current_user)


bp = Blueprint('domain', __name__, url_prefix='/domains')


@bp.route('/')
@login_required
def index():
    from modules import license as lic
    from modules import rbac
    domains = domain_service.list_domains()
    scope = rbac.user_scope_domains(current_user())
    if scope is not None:
        ids = set(scope)
        domains = [d for d in domains if d['id'] in ids]
    return render_template('domains.html', domains=domains, max_domains=lic.max_domains(),
                           max_users=lic.max_users(), task=task_queue.status())


@bp.route('/new', methods=['GET'])
@login_required
def new():
    from modules import license as lic
    return render_template('domain_form.html', mode='create', d=None,
                           debug=config.DEBUG_DOMAIN if config.ENABLE_DEBUG_DOMAIN else None,
                           max_domains=lic.max_domains(), max_users=lic.max_users())


@bp.route('/<int:domain_id>/edit', methods=['GET'])
@login_required
def edit(domain_id):
    from modules import license as lic
    row = db.query_one('SELECT * FROM ad_domain_conf WHERE id=?', (domain_id,))
    if not row:
        return render_template('error.html', code=404, message='域不存在'), 404
    d = dict(row)
    d.pop('password_enc', None)
    return render_template('domain_form.html', mode='edit', d=d,
                           debug=config.DEBUG_DOMAIN if config.ENABLE_DEBUG_DOMAIN else None,
                           max_domains=lic.max_domains(), max_users=lic.max_users())


@bp.route('/save', methods=['POST'])
@login_required
def save():
    t0 = time.time()
    try:
        domain_id = int_arg('id')
        data = request.form.to_dict()
        data['enabled'] = '1' if request.form.get('enabled', '1') in ('1', 'on', 'true') else '0'
        if domain_id:
            domain_service.update(domain_id, data)
            action, did = 'update_domain', domain_id
            msg = '域配置已更新'
        else:
            # 版本域数量硬限制
            from modules import license as lic
            current = db.scalar('SELECT COUNT(*) FROM ad_domain_conf', (), 0)
            if current >= lic.max_domains():
                raise ValueError(f'当前授权版本仅支持 {lic.max_domains()} 个域（已配置 {current} 个），请升级版本')
            did = domain_service.create(data)
            action, msg = 'create_domain', '域已添加，建议立即执行一次全量同步以加载数据'
            reload_domain_jobs()
        log_op('domain', action, target=data.get('domain_name', ''), message=msg,
               domain_id=did, duration_ms=int((time.time() - t0) * 1000))
        # 添加后自动探测一次连通性（不阻塞太久，5s 超时）
        res = domain_service.list_domains()
        return ok({'id': did, 'redirect': f'/domains/{did}/edit'}, msg,
                  domains=[{'id': r['id'], 'name': r['name'], 'status': r['status']} for r in res])
    except Exception as e:
        return api_error(e, 'domain', 'save_domain', target=request.form.get('domain_name', ''))


@bp.route('/<int:domain_id>/toggle', methods=['POST'])
@login_required
def toggle(domain_id):
    try:
        enabled = request.form.get('enabled', '0') in ('1', 'on', 'true')
        domain_service.set_enabled(domain_id, enabled)
        reload_domain_jobs()
        log_op('domain', 'toggle_domain', target=str(domain_id),
               message='启用域连接' if enabled else '停用域连接（该域进入只读）', domain_id=domain_id)
        return ok(message='域已启用' if enabled else '域已停用（该域所有写操作将被拒绝）')
    except Exception as e:
        return api_error(e, 'domain', 'toggle_domain', domain_id=domain_id)


@bp.route('/<int:domain_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete(domain_id):
    try:
        require_confirm()
        row = db.query_one('SELECT name, domain_name FROM ad_domain_conf WHERE id=?', (domain_id,))
        if not row:
            return fail('域不存在', status=404)
        res = domain_service.delete(domain_id)
        reload_domain_jobs()
        L.invalidate_conn(domain_id)
        log_op('domain', 'delete_domain', target=f"{row['name']}({row['domain_name']})",
               detail=f'仅删除系统配置与本地缓存（{res["counts"]}），AD 域本身未做任何改动',
               message='域配置已删除')
        return ok(message='域配置及其缓存已删除（AD 域本身未改动）')
    except Exception as e:
        return api_error(e, 'domain', 'delete_domain', domain_id=domain_id)


@bp.route('/<int:domain_id>/test', methods=['POST'])
@login_required
def test(domain_id):
    """连通性测试：TCP / LDAP 绑定 / 域信息 / 写权限（默认不做写探测）。"""
    try:
        d = L.get_domain(domain_id)
        deep = request.form.get('deep', '0') == '1'
        t0 = time.time()
        if deep:
            results = L.self_check(d)
        else:
            okflag, msg = L.test_connection(d)
            results = [{'name': 'LDAP 绑定', 'ok': okflag, 'msg': msg}]
        all_ok = all(r['ok'] for r in results)
        log_op('domain', 'test_domain', target=d.label, result='success' if all_ok else 'failed',
               message='连通性测试' + ('通过' if all_ok else '未通过'),
               detail='；'.join(f"{r['name']}: {r['msg']}" for r in results),
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok({'results': results, 'status': 'online' if all_ok else 'offline'},
                  '连通性测试完成' if all_ok else '连通性测试未通过', all_ok=all_ok)
    except Exception as e:
        return api_error(e, 'domain', 'test_domain', domain_id=domain_id)


@bp.route('/<int:domain_id>/sync', methods=['POST'])
@login_required
def sync(domain_id):
    """单域立即同步（入队执行，避免页面长时间挂起）。"""
    try:
        kind = request.form.get('kind', 'incr')
        d = L.get_domain(domain_id, only_enabled=True)
        if kind == 'full':
            require_confirm()
        task_id = task_queue.enqueue('sync_domain', domain_id, {'kind': kind}, operator_name())
        log_op('sync', f'manual_{kind}_sync', target=d.label, message=f'已提交{"全量" if kind == "full" else "增量"}同步任务',
               domain_id=d.id, domain_name=d.label)
        return ok({'task_id': task_id}, f'已提交{"全量" if kind == "full" else "增量"}同步任务，稍后刷新查看结果')
    except Exception as e:
        return api_error(e, 'sync', 'manual_sync', domain_id=domain_id)


@bp.route('/sync-all', methods=['POST'])
@login_required
def sync_all():
    try:
        kind = request.form.get('kind', 'incr')
        if kind == 'full':
            require_confirm()
        task_id = task_queue.enqueue('sync_all', None, {'kind': kind}, operator_name())
        log_op('sync', f'manual_{kind}_sync_all', target='全部域',
               message=f'已提交全部域{"全量" if kind == "full" else "增量"}同步（逐域串行）')
        return ok({'task_id': task_id}, '已提交全部域同步任务，将逐域串行执行')
    except Exception as e:
        return api_error(e, 'sync', 'manual_sync_all')


@bp.route('/refresh-status', methods=['POST'])
@login_required
def refresh_status():
    try:
        t0 = time.time()
        results = domain_service.refresh_status_all()
        for r in results:
            log_op('domain', 'check_status', target=r['name'], result='success' if r['ok'] else 'failed',
                   message=r['msg'])
        online = sum(1 for r in results if r['ok'])
        return ok({'results': results}, f'已检测 {len(results)} 个域，在线 {online} 个')
    except Exception as e:
        return api_error(e, 'domain', 'refresh_status')


@bp.route('/api/status')
@login_required
def api_status():
    """轮询用：域同步状态 + 任务进度。"""
    return ok({'domains': sync_task.status_summary()['domains'], 'task': task_queue.status(),
               'trust': ad_trust.trust_summary()['count']})


@bp.route('/api/tasks')
@login_required
def api_tasks():
    return ok(task_queue.status())
