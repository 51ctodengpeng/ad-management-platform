# -*- coding: utf-8 -*-
"""林间信任：列表、一键新建（高危）、撤销（高危）、状态刷新"""
import re
import time

from flask import Blueprint, render_template, request

import config
from modules import db
from modules import ad_ldap as L
from modules import ad_trust as T
from modules import task_queue
from routes.common import (login_required, ok, fail, api_error, log_op, require_confirm,
                           int_arg, operator_name, client_ip, feature_guard)

bp = Blueprint('trust', __name__, url_prefix='/trust')
bp.before_request(feature_guard('trust'))


@bp.route('/')
@login_required
def index():
    summary = T.trust_summary()
    domains = L.load_domains()
    dm = {d.id: d for d in domains}
    return render_template('trust.html', trusts=summary['trusts'], count=summary['count'],
                           verified=summary['verified'], domains=domains, dm=dm,
                           direction_text=T.DIRECTION_TEXT, type_text=T.TYPE_TEXT)


@bp.route('/new')
@login_required
def new():
    domains = L.load_domains(only_enabled=True)
    return render_template('trust_form.html', domains=domains,
                           debug=config.DEBUG_DOMAIN if config.ENABLE_DEBUG_DOMAIN else None,
                           direction_text=T.DIRECTION_TEXT)


@bp.route('/create', methods=['POST'])
@login_required
def create():
    """一键创建林间信任 —— 高危操作，强制二次确认。"""
    t0 = time.time()
    local_id = int_arg('local_id')
    remote_id = int_arg('remote_id')
    direction = request.form.get('direction', 'bidirectional')
    try:
        require_confirm()
        if not local_id:
            return fail('请选择本地林')
        if direction not in ('bidirectional', 'outbound'):
            return fail('信任方向仅支持「双向」或「出站」（对方信任本林的单向关系需在对方林侧创建）')
        if remote_id and remote_id == local_id:
            return fail('不能选择同一个林建立信任')
        remote_cred = None
        if not remote_id:
            remote_cred = {
                'domain_name': request.form.get('remote_domain_name', '').strip(),
                'dc_host': request.form.get('remote_dc_host', '').strip(),
                'username': request.form.get('remote_username', '').strip(),
                'password': request.form.get('remote_password', ''),
            }
            if not remote_cred['domain_name']:
                return fail('请选择对方林，或手动填写对方 AD 域名')
        dry = request.form.get('dry_run') == '1'
        res = T.create_trust(local_id, remote_id, operator=operator_name(), ip=client_ip(),
                             direction=direction, remote_cred=remote_cred, dry_run=dry)
        return ok(res, res.get('message', '完成'),
                  duration=int((time.time() - t0) * 1000))
    except T.TrustError as e:
        log_op('trust', 'create_trust', target=request.form.get('remote_domain_name', '') or str(remote_id),
               result='failed', message=str(e), domain_id=local_id,
               duration_ms=int((time.time() - t0) * 1000))
        return fail(str(e), code='trust_failed', steps=[])
    except Exception as e:
        return api_error(e, 'trust', 'create_trust', domain_id=local_id)


@bp.route('/preflight', methods=['POST'])
@login_required
def preflight():
    """创建前的连通性预检（不产生任何变更），用于表单上的"预检"按钮。"""
    try:
        local_id = int_arg('local_id')
        remote_id = int_arg('remote_id')
        if not local_id:
            return fail('请选择本地林')
        a = L.get_domain(local_id)
        data = {'local': {'domain': a.domain_name, 'host': a.dc_host, 'results': T.preflight(a, True)}}
        if remote_id:
            b = L.get_domain(remote_id)
            data['remote'] = {'domain': b.domain_name, 'host': b.dc_host, 'results': T.preflight(b, False)}
        return ok(data, '预检完成')
    except Exception as e:
        return api_error(e, 'trust', 'preflight')


@bp.route('/refresh', methods=['POST'])
@login_required
def refresh():
    try:
        domain_id = int_arg('domain_id')
        if domain_id:
            res = T.refresh_trusts(domain_id)
        else:
            task_id = task_queue.enqueue('trust_refresh', None, {}, 'system')
            return ok({'task_id': task_id}, '已提交信任状态刷新任务')
        return ok(res, res.get('message', ''))
    except Exception as e:
        return api_error(e, 'trust', 'refresh_trust')


@bp.route('/remove', methods=['POST'])
@login_required
def remove():
    """撤销信任（高危）。提供对方林管理员凭据时双向删除，否则仅删除本林侧。"""
    try:
        require_confirm()
        local_id = int_arg('local_id')
        partner = request.form.get('partner', '')
        if not local_id or not partner:
            return fail('缺少参数')
        res = T.delete_trust(local_id, partner, operator_name(), client_ip(),
                             remote_user=request.form.get('remote_user', '').strip(),
                             remote_pwd=request.form.get('remote_pwd', ''))
        return ok(res, res.get('message', '已撤销'))
    except T.TrustError as e:
        return fail(str(e), code='trust_failed')
    except Exception as e:
        return api_error(e, 'trust', 'remove_trust')
