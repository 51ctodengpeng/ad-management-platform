# -*- coding: utf-8 -*-
"""AD 用户组管理（按域隔离）：查询、新增、编辑、删除、批量增删成员"""
import time

from flask import Blueprint, render_template, request

import config
from modules import db
from modules import ad_ldap as L
from modules import query_service as Q
from modules import sync_task
from modules import recycle_bin
from routes.common import (login_required, ok, fail, api_error, log_op, int_arg, page_args,
                           guard_write, require_confirm, batch_lock, operator_name)

bp = Blueprint('groups', __name__, url_prefix='/groups')


@bp.route('/')
@login_required
def index():
    domains = L.load_domains()
    domain_id = int_arg('domain_id')
    f = {'domain_id': domain_id, 'keyword': request.args.get('keyword', '').strip(),
         'scope': request.args.get('scope', ''), 'category': request.args.get('category', '')}
    page, size = page_args(20)
    rows, total = Q.list_groups(f, page, size, request.args.get('sort', 'name'),
                                request.args.get('order', 'asc'))
    dm = {d.id: d for d in domains}
    return render_template('groups.html', groups=rows, total=total, f=f, domains=domains, dm=dm,
                           page=Q.pagination(total, page, size), d=dm.get(domain_id),
                           protected=config.PROTECTED_GROUPS)


@bp.route('/<int:gid>')
@login_required
def detail(gid):
    row = db.query_one('SELECT * FROM ad_group_cache WHERE id=?', (gid,))
    if not row:
        return render_template('error.html', code=404, message='用户组不存在'), 404
    d = L.get_domain(row['domain_id'])
    # 组成员直接从 AD 实时读取（详情页按需，量小）
    members, err = [], ''
    try:
        conn = L.get_connection(d)
        conn.search(row['dn'], '(objectClass=*)', search_scope='BASE',
                    attributes=['member', 'memberOf'], size_limit=1)
        dns = L._entry_value(conn.entries[0], 'member') or []
        if not isinstance(dns, list):
            dns = [dns]
        if dns:
            marks = ','.join('?' * len(dns))
            members = db.query(f'SELECT * FROM ad_user_cache WHERE domain_id=? AND dn IN ({marks}) ORDER BY sam_account_name',
                               (d.id, *dns))
    except Exception as e:
        err = e.message if isinstance(e, L.ADError) else str(e)
    return render_template('group_detail.html', g=row, d=d, members=members, err=err,
                           is_protected=(row['sam_account_name'] or '') in config.PROTECTED_GROUPS)


@bp.route('/api/options')
@login_required
def api_options():
    """用户组下拉选项（加组、批量加组用）。"""
    try:
        d = L.get_domain(int_arg('domain_id'))
        kw = request.args.get('keyword', '').strip()
        where, params = 'domain_id=?', [d.id]
        if kw:
            where += ' AND (name LIKE ? OR sam_account_name LIKE ?)'
            params += [f'%{kw}%', f'%{kw}%']
        rows = db.query(f'SELECT dn, name, sam_account_name, scope FROM ad_group_cache WHERE {where} '
                        f'ORDER BY name LIMIT 1000', tuple(params))
        return ok([dict(r) | {'label': f"{r['name']}（{r['scope']}）"} for r in rows])
    except Exception as e:
        return api_error(e, 'group', 'group_options')


@bp.route('/create', methods=['POST'])
@login_required
def create():
    t0 = time.time()
    domain_id = int_arg('domain_id')
    try:
        d = guard_write(domain_id)
        data = request.form.to_dict()
        dn = L.create_group(d, data)
        sync_task.upsert_group(d, {'domain_id': d.id, 'dn': dn, 'name': data.get('name', ''),
                                   'sam_account_name': data.get('sam_account_name') or data.get('name', ''),
                                   'scope': data.get('scope', 'Global'), 'category': data.get('category', 'Security'),
                                   'description': data.get('description', ''), 'mail': data.get('mail', ''),
                                   'ou_dn': (data.get('ou_dn') or f'CN=Users,{d.base_dn}'),
                                   'member_count': 0, 'usn': 0})
        log_op('group', 'create_group', target=dn, message='新增用户组成功', domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok({'dn': dn}, f'用户组「{data.get("name")}」已创建')
    except Exception as e:
        return api_error(e, 'group', 'create_group', domain_id=domain_id)


@bp.route('/<int:gid>/update', methods=['POST'])
@login_required
def update(gid):
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_group_cache WHERE id=?', (gid,))
    if not row:
        return fail('用户组不存在', status=404)
    try:
        d = guard_write(row['domain_id'])
        data = request.form.to_dict()
        L.update_group(d, row['dn'], data)
        db.execute('UPDATE ad_group_cache SET description=?, mail=? WHERE id=?',
                   (data.get('description', ''), data.get('mail', ''), gid))
        log_op('group', 'update_group', target=row['dn'], message='编辑用户组成功',
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok(message='用户组已更新')
    except Exception as e:
        return api_error(e, 'group', 'update_group', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:gid>/delete', methods=['POST'])
@login_required
def delete(gid):
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_group_cache WHERE id=?', (gid,))
    if not row:
        return fail('用户组不存在', status=404)
    try:
        require_confirm()
        if (row['sam_account_name'] or '') in config.PROTECTED_GROUPS:
            return fail(f'「{row["sam_account_name"]}」为 AD 受保护的内置组，禁止删除')
        d = guard_write(row['domain_id'])
        recycle_bin.add('group', d.id, row['name'] or row['sam_account_name'], row['dn'],
                        dict(row), operator_name())
        L.delete_group(d, row['dn'])
        db.execute('DELETE FROM ad_group_cache WHERE id=?', (gid,))
        log_op('group', 'delete_group', target=row['dn'], message='删除用户组成功（已移入回收站）',
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok(message='用户组已删除（已移入回收站）')
    except Exception as e:
        return api_error(e, 'group', 'delete_group', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:gid>/members', methods=['POST'])
@login_required
def members(gid):
    """批量添加 / 移除成员（单次上限 BATCH_LIMIT）。"""
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_group_cache WHERE id=?', (gid,))
    if not row:
        return fail('用户组不存在', status=404)
    try:
        d = guard_write(row['domain_id'])
        action = request.form.get('action', 'add')
        dns = request.form.getlist('member_dns') or []
        if not dns:
            return fail('请选择要操作的成员')
        if len(dns) > config.BATCH_LIMIT:
            return fail(f'单次最多 {config.BATCH_LIMIT} 个成员')
        with batch_lock(timeout=300):
            if action == 'add':
                L.add_group_members(d, row['dn'], dns)
                msg = f'已添加 {len(dns)} 个成员'
            else:
                L.remove_group_members(d, row['dn'], dns)
                msg = f'已移除 {len(dns)} 个成员'
        # 成员数刷新
        db.execute("UPDATE ad_group_cache SET member_count=MAX(0, member_count + ?) WHERE id=?",
                   (len(dns) if action == 'add' else -len(dns), gid))
        log_op('group', f'{action}_members', target=row['dn'], detail=str(dns[:50]), message=msg,
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok(message=msg)
    except Exception as e:
        return api_error(e, 'group', 'change_members', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:gid>/candidates')
@login_required
def candidates(gid):
    """可加入该组的用户（缓存中、同域、且不在组内由前端过滤）。"""
    row = db.query_one('SELECT * FROM ad_group_cache WHERE id=?', (gid,))
    if not row:
        return fail('用户组不存在', status=404)
    kw = request.args.get('keyword', '').strip()
    where = 'domain_id=?'
    params = [row['domain_id']]
    if kw:
        where += ' AND (sam_account_name LIKE ? OR display_name LIKE ?)'
        params += [f'%{kw}%', f'%{kw}%']
    rows = db.query(f'SELECT id, dn, sam_account_name, display_name, department FROM ad_user_cache '
                    f'WHERE {where} ORDER BY sam_account_name LIMIT 300', tuple(params))
    return ok([dict(r) for r in rows])
