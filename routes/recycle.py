# -*- coding: utf-8 -*-
"""回收站：软删除对象列表、还原、永久删除。"""
from flask import Blueprint, render_template, request

from modules import ad_ldap as L
from modules import recycle_bin
from routes.common import (login_required, ok, fail, api_error, log_op, require_confirm, feature_guard)

bp = Blueprint('recycle', __name__, url_prefix='/recycle')
bp.before_request(feature_guard('recycle'))


@bp.route('/')
@login_required
def index():
    items = recycle_bin.list_items()
    domains = L.load_domains()
    return render_template('recycle.html', items=items, domains=domains)


@bp.route('/<int:item_id>/restore', methods=['POST'])
@login_required
def restore(item_id):
    try:
        require_confirm()
        mode = request.form.get('mode', 'rename')
        new_password = request.form.get('new_password', '')
        res = recycle_bin.restore(item_id, mode, new_password)
        if not res.get('ok'):
            if res.get('conflict'):
                return ok(res, res.get('message'), conflict=True)
            return fail(res.get('message', '还原失败'))
        log_op('recycle', 'restore', target=str(item_id), message=res.get('message', '已还原'))
        return ok(res, res.get('message', '已还原'))
    except Exception as e:
        return api_error(e, 'recycle', 'restore')


@bp.route('/<int:item_id>/purge', methods=['POST'])
@login_required
def purge(item_id):
    try:
        require_confirm()
        recycle_bin.purge(item_id)
        log_op('recycle', 'purge', target=str(item_id), message='已永久删除')
        return ok(message='已永久删除')
    except Exception as e:
        return api_error(e, 'recycle', 'purge')


@bp.route('/purge-all', methods=['POST'])
@login_required
def purge_all():
    try:
        require_confirm()
        n = recycle_bin.purge_all()
        log_op('recycle', 'purge_all', target='回收站', message=f'清空 {n} 条')
        return ok(message=f'已清空 {n} 条记录')
    except Exception as e:
        return api_error(e, 'recycle', 'purge_all')
