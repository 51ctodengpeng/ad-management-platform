# -*- coding: utf-8 -*-
"""许可授权页：试用状态展示、许可文件导入激活。"""
from flask import Blueprint, render_template, request

from modules import license as lic
from routes.common import login_required, ok, fail, api_error, log_op

bp = Blueprint('license', __name__, url_prefix='/license')


@bp.route('/')
@login_required
def index():
    return render_template('license.html', state=lic.get_state(), feats=lic.feature_list())


@bp.route('/api/state')
@login_required
def api_state():
    return ok(lic.get_state())


@bp.route('/import', methods=['POST'])
@login_required
def import_license():
    try:
        # 支持两种方式：上传 .lic 文件，或直接粘贴许可 JSON 文本
        f = request.files.get('file')
        if f and f.filename:
            raw = f.read().decode('utf-8', errors='replace')
        else:
            raw = (request.form.get('text') or '').strip()
        if not raw:
            return fail('请上传许可文件，或粘贴许可内容')
        if len(raw) > 1024 * 1024:
            return fail('许可内容过大')
        res = lic.verify_and_activate(raw)
        if not res.get('ok'):
            return fail(res.get('message', '激活失败'))
        log_op('license', 'activate', target=res.get('customer', '') or 'unknown',
               message='许可激活成功')
        return ok(res, '激活成功')
    except Exception as e:
        return api_error(e, 'license', 'import')
