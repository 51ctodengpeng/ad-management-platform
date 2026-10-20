# -*- coding: utf-8 -*-
"""日志审计：搜索、筛选（按域）、导出、自动维护（归档+VACUUM）"""
import io
import time

from flask import Blueprint, render_template, request, send_file

import config
from modules import db
from modules import ad_ldap as L
from modules import log_service
from modules import excel_service
from routes.common import login_required, admin_required, ok, fail, api_error, log_op, int_arg, page_args, require_confirm

bp = Blueprint('logs', __name__, url_prefix='/logs')


def _filters():
    return {
        'domain_id': int_arg('domain_id'),
        'module': request.args.get('module', ''),
        'result': request.args.get('result', ''),
        'operator': request.args.get('operator', '').strip(),
        'keyword': request.args.get('keyword', '').strip(),
        'date_from': request.args.get('date_from', ''),
        'date_to': request.args.get('date_to', ''),
    }


@bp.route('/')
@login_required
def index():
    f = _filters()
    page, size = page_args(30, 200)
    rows, total = log_service.search(f, page, size)
    domains = L.load_domains()
    from modules.query_service import pagination
    return render_template('logs.html', logs=rows, total=total, f=f, domains=domains,
                           page=pagination(total, page, size), modules=log_service.MODULE_NAMES,
                           retention=config.LOG_RETENTION_DAYS)


@bp.route('/export')
@login_required
def export():
    try:
        scope = request.args.get('scope', 'current')
        f = {} if scope == 'all' else _filters()
        data = excel_service.export_logs(f)
        log_op('system', 'export_logs', target='操作日志',
               message='导出全部日志' if scope == 'all' else '导出日志')
        return send_file(io.BytesIO(data), as_attachment=True,
                         download_name=f'操作日志_{time.strftime("%Y%m%d_%H%M%S")}.xlsx',
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as e:
        return api_error(e, 'system', 'export_logs')


@bp.route('/maintain', methods=['POST'])
@login_required
@admin_required
def maintain():
    """手动触发日志维护（高危：会删除 90 天前日志，先归档）。"""
    try:
        require_confirm()
        res = log_service.maintain()
        return ok(res, f'维护完成：归档 {res["deleted"]} 条并 VACUUM'
                       + ('' if res['vacuum'] else '（VACUUM 被占用，稍后自动重试）'))
    except Exception as e:
        return api_error(e, 'system', 'log_maintain')


@bp.route('/clear', methods=['POST'])
@login_required
@admin_required
def clear():
    """手动「全部清理」：清空全部操作日志（先归档到 gzip csv），需二次确认。"""
    try:
        require_confirm()
        archive = request.form.get('archive', '1') == '1'
        res = log_service.clear_all(archive=archive)
        msg = f'全部清理完成：删除 {res["deleted"]} 条'
        if res.get('archived_file'):
            msg += '（已先归档备份）'
        if not res.get('vacuum'):
            msg += '；VACUUM 被占用，稍后自动重试'
        return ok(res, msg)
    except Exception as e:
        return api_error(e, 'system', 'log_clear_all')


@bp.route('/api/stats')
@login_required
def stats():
    rows = db.query("SELECT module, result, COUNT(*) c FROM ad_operation_log "
                    "WHERE created_at>=datetime('now','localtime','-7 days') GROUP BY module, result")
    return ok([dict(r) for r in rows])
