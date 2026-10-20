# -*- coding: utf-8 -*-
"""安全中心（仅企业版）：安全态势体检 + 异常登录检测。"""
import io
import time

from flask import Blueprint, render_template, send_file

from modules import security_center as SC
from modules import excel_service
from routes.common import login_required, feature_guard, ok, api_error, log_op

bp = Blueprint('security', __name__, url_prefix='/security')
bp.before_request(feature_guard('security_center'))


@bp.route('/')
@login_required
def index():
    return render_template('security.html')


@bp.route('/api/posture')
@login_required
def api_posture():
    """一键巡检：扫描所有已纳管域，返回安全评分与风险清单。"""
    try:
        res = SC.scan_all()
        log_op('security', 'posture_scan', target='安全态势体检',
               message=f"总评分 {res['overall_score']}，高危 {res['high']} / 中危 {res['medium']} / 低危 {res['low']}")
        return ok(res)
    except Exception as e:
        return api_error(e, 'security', 'posture_scan')


@bp.route('/api/anomalies')
@login_required
def api_anomalies():
    """异常登录检测。"""
    try:
        res = SC.detect_anomalies()
        log_op('security', 'anomaly_scan', target='异常登录检测',
               message=f"发现 {len(res['items'])} 类异常")
        return ok(res)
    except Exception as e:
        return api_error(e, 'security', 'anomaly_scan')


@bp.route('/export')
@login_required
def export():
    """导出安全态势体检报告（Excel）。"""
    try:
        res = SC.scan_all()
        data = excel_service.export_security_report(res)
        log_op('security', 'export', target='安全态势体检报告', message='导出体检报告')
        return send_file(io.BytesIO(data), as_attachment=True,
                         download_name=f'安全态势体检_{time.strftime("%Y%m%d_%H%M%S")}.xlsx',
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as e:
        return api_error(e, 'security', 'export')
