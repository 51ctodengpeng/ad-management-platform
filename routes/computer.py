# -*- coding: utf-8 -*-
"""域计算机管理（按域隔离）：列表、离线识别、信息编辑、启停、本系统备注"""
import io
import time

from flask import Blueprint, render_template, request, send_file

import config
from modules import db
from modules import ad_ldap as L
from modules import query_service as Q
from modules import sync_task
from modules import excel_service
from modules import recycle_bin
from routes.common import (login_required, ok, fail, api_error, log_op, int_arg, page_args, guard_write,
                           require_confirm, operator_name, batch_lock)

bp = Blueprint('computers', __name__, url_prefix='/computers')


@bp.route('/')
@login_required
def index():
    domains = L.load_domains()
    domain_id = int_arg('domain_id')
    f = {'domain_id': domain_id, 'keyword': request.args.get('keyword', '').strip(),
         'enabled': request.args.get('enabled', 'all'),
         'offline': 1 if request.args.get('offline') == '1' else None}
    page, size = page_args(20, 1000)
    rows, total = Q.list_computers(f, page, size, request.args.get('sort', 'name'),
                                   request.args.get('order', 'asc'))
    dm = {d.id: d for d in domains}
    # 离线基准线（30 天前），供模板判断"长期离线"；避免在模板里做日期运算
    offline_line = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 30 * 86400))
    return render_template('computers.html', computers=rows, total=total, f=f, domains=domains, dm=dm,
                           page=Q.pagination(total, page, size), d=dm.get(domain_id),
                           offline_line=offline_line)


@bp.route('/<int:cid>/update', methods=['POST'])
@login_required
def update(cid):
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_computer_cache WHERE id=?', (cid,))
    if not row:
        return fail('计算机不存在', status=404)
    try:
        data = request.form.to_dict()
        # 备注只写本地缓存（不污染 AD description），AD 描述按用户明确输入才写回
        if data.get('remark') is not None:
            db.execute("UPDATE ad_computer_cache SET remark=?, remark_updated_by=?, "
                       "remark_updated_at=datetime('now','localtime') WHERE id=?",
                       (data.get('remark', '').strip(), _operator(), cid))
        ad_changed = False
        if data.get('description') is not None and data.get('description') != (row['description'] or ''):
            d = guard_write(row['domain_id'])
            L.update_computer(d, row['dn'], {'description': data.get('description', '')})
            db.execute('UPDATE ad_computer_cache SET description=? WHERE id=?', (data.get('description'), cid))
            ad_changed = True
        log_op('computer', 'update_computer', target=row['dn'],
               detail='写回 AD 描述' if ad_changed else '仅更新本地备注',
               message='计算机信息已更新', domain_id=row['domain_id'],
               duration_ms=int((time.time() - t0) * 1000))
        return ok(message='计算机信息已更新')
    except Exception as e:
        return api_error(e, 'computer', 'update_computer', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:cid>/toggle', methods=['POST'])
@login_required
def toggle(cid):
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_computer_cache WHERE id=?', (cid,))
    if not row:
        return fail('计算机不存在', status=404)
    try:
        d = guard_write(row['domain_id'])
        enable = request.form.get('enabled', '0') in ('1', 'on', 'true')
        if not enable:
            require_confirm()
        L.set_computer_enabled(d, row['dn'], enable)
        db.execute('UPDATE ad_computer_cache SET enabled=? WHERE id=?', (1 if enable else 0, cid))
        msg = '计算机账号已启用' if enable else '计算机账号已禁用（该设备将无法登录域）'
        log_op('computer', 'enable_computer' if enable else 'disable_computer', target=row['dn'],
               message=msg, domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok(message=msg)
    except Exception as e:
        return api_error(e, 'computer', 'toggle_computer', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:cid>/delete', methods=['POST'])
@login_required
def delete(cid):
    """删除计算机账户（高危：直连 AD 删除，需二次确认）。"""
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_computer_cache WHERE id=?', (cid,))
    if not row:
        return fail('计算机不存在，请刷新列表', status=404)
    try:
        require_confirm()
        d = guard_write(row['domain_id'])
        recycle_bin.add('computer', d.id, row['name'], row['dn'], dict(row), operator_name())
        L.delete_computer(d, row['dn'])
        sync_task.delete_computer_cache(d, row['dn'])
        log_op('computer', 'delete_computer', target=row['dn'], result='success',
               detail=f"计算机名 {row['name']}（已移入回收站）", message='删除计算机账户成功',
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok(message='计算机账户已删除（已移入回收站）')
    except Exception as e:
        return api_error(e, 'computer', 'delete_computer', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/batch-delete', methods=['POST'])
@login_required
def batch_delete():
    """批量删除计算机账户（高危：直连 AD，需二次确认，逐条移入回收站）。"""
    t0 = time.time()
    try:
        require_confirm()
        ids = request.form.getlist('ids[]') or request.form.getlist('ids')
        if not ids:
            raise ValueError('未选择任何计算机')
        ids = [int(i) for i in ids if str(i).isdigit()]
        if len(ids) > config.BATCH_LIMIT:
            raise ValueError(f'单次批量操作上限 {config.BATCH_LIMIT} 条，请分批执行')
        marks = ','.join('?' * len(ids))
        rows = db.query(f'SELECT * FROM ad_computer_cache WHERE id IN ({marks})', tuple(ids))
        if not rows:
            raise ValueError('所选计算机已不在缓存中，请刷新列表')
        domain_ids = {r['domain_id'] for r in rows}
        if len(domain_ids) > 1:
            raise ValueError('批量删除仅支持同一域内的计算机，请按域筛选后再执行')
        d = guard_write(domain_ids.pop())
        success, failed = [], []
        with batch_lock(timeout=300):
            for r in rows:
                try:
                    recycle_bin.add('computer', d.id, r['name'], r['dn'], dict(r), operator_name())
                    L.delete_computer(d, r['dn'])
                    sync_task.delete_computer_cache(d, r['dn'])
                    success.append(r['name'])
                except Exception as e:
                    msg = e.message if isinstance(e, L.ADError) else str(e)
                    failed.append({'name': r['name'], 'error': msg})
        msg = f'批量删除完成：成功 {len(success)} 台' + (f'，失败 {len(failed)} 台' if failed else '')
        log_op('computer', 'batch_delete', target=f'共 {len(rows)} 台计算机',
               result='success' if not failed else 'failed',
               detail=f'成功：{", ".join(success[:50])}；失败：{failed[:20]}',
               message=msg, domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok({'success': success, 'failed': failed}, msg)
    except Exception as e:
        return api_error(e, 'computer', 'batch_delete', target='批量删除')


@bp.route('/export')
@login_required
def export():
    try:
        did = int_arg('domain_id')
        if not did:
            return fail('请选择要导出的域')
        data = excel_service.export_computers([did])
        log_op('computer', 'export_computers', target=str(did), message='导出计算机清单', domain_id=did)
        return send_file(io.BytesIO(data), as_attachment=True,
                         download_name=f'域计算机_{time.strftime("%Y%m%d_%H%M%S")}.xlsx',
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as e:
        return api_error(e, 'computer', 'export_computers')


def _operator():
    from flask import g
    u = getattr(g, 'user', None)
    return u['username'] if u else 'system'
