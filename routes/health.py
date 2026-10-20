# -*- coding: utf-8 -*-
"""AD 域控健康监控（仅企业版）：实时采集 / 一键巡检 / 结果导出。"""
import io
import time

from flask import Blueprint, render_template, request, send_file

from modules import ad_health
from modules import excel_service
from modules import ad_ldap as L
from routes.common import login_required, ok, fail, api_error, log_op, feature_guard

bp = Blueprint('health', __name__, url_prefix='/health')
bp.before_request(feature_guard('health'))   # 仅企业版可用


@bp.route('/')
@login_required
def index():
    domains = L.load_domains()
    return render_template('health.html', domains=domains)


@bp.route('/api/summary')
@login_required
def api_summary():
    """实时采集：deep=1 时含复制/资源（较慢），默认仅连接状态（快）。"""
    try:
        deep = request.args.get('deep') == '1'
        return ok(ad_health.summarize(deep=deep))
    except Exception as e:
        return api_error(e, 'health', 'summary')


@bp.route('/check', methods=['POST'])
@login_required
def check():
    """一键巡检：采集连接 + 复制 + 资源，汇总异常项。"""
    t0 = time.time()
    try:
        res = ad_health.summarize(deep=True)
        s = res['stat']
        log_op('health', 'inspect', target=f"{s['total']} 个域控",
               result='success' if (s['critical'] + s['offline']) == 0 else 'failed',
               message=f"巡检完成：健康 {s['healthy']} / 告警 {s['warning']} / 严重 {s['critical']} / 离线 {s['offline']}",
               duration_ms=int((time.time() - t0) * 1000))
        return ok(res, f"巡检完成：共 {s['total']} 个域控，发现异常项 {res['issues_total']} 个")
    except Exception as e:
        return api_error(e, 'health', 'inspect')


@bp.route('/export')
@login_required
def export():
    """导出巡检结果（Excel）。"""
    try:
        res = ad_health.summarize(deep=True)
        data = excel_service.export_health(res['domains'])
        log_op('health', 'export', target=f"{len(res['domains'])} 个域控", message='导出巡检结果')
        return send_file(io.BytesIO(data), as_attachment=True,
                         download_name=f'域控巡检_{time.strftime("%Y%m%d_%H%M%S")}.xlsx',
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as e:
        return api_error(e, 'health', 'export')
