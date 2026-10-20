# -*- coding: utf-8 -*-
"""AD 用户管理：列表/详情/新增/编辑/启停/解锁/重置密码/移动OU/加组/批量/导入导出
铁律：写操作直连 AD，成功后单条刷新缓存；失败不改缓存。列表全部读缓存。
"""
import io
import time

from flask import Blueprint, render_template, request, send_file, Response

import config
from modules import db
from modules import ad_ldap as L
from modules import query_service as Q
from modules import sync_task
from modules import excel_service
from modules import recycle_bin
from modules.security import password_strength_error, generate_password
from routes.common import (login_required, ok, fail, api_error, log_op, int_arg, page_args,
                           guard_write, require_confirm, operator_name, client_ip, batch_lock,
                           feature_required, permission_required)

bp = Blueprint('users', __name__, url_prefix='/users')


def _filters():
    return {
        'domain_id': int_arg('domain_id'),
        'keyword': request.values.get('keyword', '').strip(),
        'enabled': request.values.get('enabled', 'all'),
        'department': request.values.get('department', ''),
        'ou_dn': request.values.get('ou_dn', ''),
        'tag': request.values.get('tag', ''),
    }


def _check_max_users(domain_id: int, adding: int = 1):
    """单域用户上限硬限制：写入前校验（标准 2000 / 专业 10000 / 企业 20000）。"""
    from modules import license as lic
    limit = lic.max_users()
    current = db.scalar('SELECT COUNT(*) FROM ad_user_cache WHERE domain_id=?', (domain_id,), 0)
    if current + adding > limit:
        d = L.get_domain(domain_id)
        raise ValueError(
            f'当前授权版本单域用户上限为 {limit} 个（域「{d.label}」已有 {current} 个），'
            f'本次新增 {adding} 个将超出上限，请升级版本或减少数量')


@bp.route('/')
@login_required
def index():
    f = _filters()
    page, size = page_args(20, 1000)
    sort = request.args.get('sort', 'sam')
    order = request.args.get('order', 'asc')
    rows, total = Q.search_users(f, page, size, sort, order)
    domains = L.load_domains()
    dm = {d.id: d for d in domains}
    tree = Q.ou_tree(f['domain_id']) if f['domain_id'] else None
    depts = Q.departments(f['domain_id']) if f['domain_id'] else []
    return render_template(
        'users.html', users=rows, total=total, f=f, domains=domains, dm=dm,
        page=Q.pagination(total, page, size), sort=sort, order=order,
        tree=tree, depts=depts, now_str=time.strftime('%Y-%m-%d %H:%M:%S'),
        cur_domain=dm.get(f['domain_id']) if f['domain_id'] else None)


@bp.route('/api/list')
@login_required
def api_list():
    f = _filters()
    page, size = page_args(20, 1000)
    rows, total = Q.search_users(f, page, size, request.args.get('sort', 'sam'),
                                 request.args.get('order', 'asc'))
    dm = L.domain_map()
    data = []
    for r in rows:
        item = dict(r)
        item['domain_label'] = dm[r['domain_id']].domain_name if r['domain_id'] in dm else ''
        data.append(item)
    return ok({'rows': data, 'pagination': Q.pagination(total, page, size)})


@bp.route('/facets')
@login_required
def facets():
    """表单用的候选项：部门、OU 数量等（只读缓存）。"""
    try:
        d = L.get_domain(int_arg('domain_id'))
        return ok({'departments': Q.departments(d.id),
                   'ous': db.scalar('SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=?', (d.id,), 0),
                   'domain_name': d.domain_name, 'base_dn': d.base_dn})
    except Exception as e:
        return api_error(e, 'user', 'facets')


@bp.route('/<int:uid>')
@login_required
def detail(uid):
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return render_template('error.html', code=404, message='用户不存在或缓存已刷新，请返回列表重试'), 404
    d = L.get_domain(row['domain_id'])
    realtime = L.user_realtime(d, row['dn'])
    tree = Q.ou_tree(d.id)
    # 所属组：从 AD 实时（详情页允许实时），失败则提示
    groups, group_err = [], ''
    if realtime.get('ok'):
        dm = L.domain_map()
        dns = realtime.get('groups') or []
        if dns:
            marks = ','.join('?' * len(dns))
            groups = db.query(f'SELECT * FROM ad_group_cache WHERE domain_id=? AND dn IN ({marks}) ORDER BY name',
                              (d.id, *dns))
    else:
        group_err = realtime.get('error', '')
    return render_template('user_detail.html', u=row, d=d, rt=realtime, tree=tree,
                           groups=groups, group_err=group_err)


@bp.route('/new')
@login_required
def new():
    domain_id = int_arg('domain_id', 1)
    domains = L.load_domains(only_enabled=True)
    if not domains:
        return render_template('error.html', code=400, message='还没有可用（已启用）的域，请先在"多域管理"中配置'), 400
    d = L.get_domain(domain_id if any(x.id == domain_id for x in domains) else domains[0].id)
    tree = Q.ou_tree(d.id)
    return render_template('user_form.html', mode='create', u=None, d=d, domains=domains, tree=tree)


@bp.route('/<int:uid>/edit')
@login_required
def edit(uid):
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return render_template('error.html', code=404, message='用户不存在'), 404
    d = L.get_domain(row['domain_id'])
    return render_template('user_form.html', mode='edit', u=row, d=d, domains=[d], tree=Q.ou_tree(d.id))


@bp.route('/create', methods=['POST'])
@permission_required('user', 'create')
@login_required
def create():
    t0 = time.time()
    domain_id = int_arg('domain_id')
    target = request.form.get('sam_account_name', '')
    try:
        d = guard_write(domain_id)
        _check_max_users(domain_id)
        data = request.form.to_dict()
        pwd = data.get('password') or ''
        if data.get('password_mode') == 'random':
            pwd = generate_password()
        err = password_strength_error(pwd)
        if err:
            return fail(err)
        data['password'] = pwd
        res = L.create_user(d, data)
        sync_task.refresh_user_by_dn(d, res['dn'])
        log_op('user', 'create_user', target=res['dn'], result='success',
               detail=f"登录名 {res['sam_account_name']}，OU {data.get('ou_dn', '')}",
               message='新增用户成功', domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok({'dn': res['dn'], 'password': pwd},
                  f"用户 {res['sam_account_name']} 创建成功" +
                  (f'，初始密码：{pwd}（请立即记录）' if data.get('password_mode') == 'random' else ''))
    except Exception as e:
        return api_error(e, 'user', 'create_user', target=target, domain_id=domain_id)


@bp.route('/<int:uid>/update', methods=['POST'])
@permission_required('user', 'edit')
@login_required
def update(uid):
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return fail('用户不存在，请刷新列表', status=404)
    try:
        d = guard_write(row['domain_id'])
        data = request.form.to_dict()
        res = L.update_user(d, row['dn'], data)
        sync_task.refresh_user_by_dn(d, res['dn'], old_dn=res['old_dn'])
        log_op('user', 'update_user', target=res['dn'], result='success',
               detail=f"修改字段：{', '.join(k for k in data if k not in ('domain_id', 'confirm'))}",
               message='编辑用户成功', domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok({'dn': res['dn']}, '用户信息已更新')
    except Exception as e:
        return api_error(e, 'user', 'update_user', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:uid>/toggle', methods=['POST'])
@login_required
def toggle(uid):
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return fail('用户不存在，请刷新列表', status=404)
    try:
        d = guard_write(row['domain_id'])
        enable = request.form.get('enabled', '0') in ('1', 'on', 'true')
        L.set_enabled(d, row['dn'], enable)
        sync_task.refresh_user_by_dn(d, row['dn'])
        msg = '账号已启用' if enable else '账号已禁用'
        log_op('user', 'enable_user' if enable else 'disable_user', target=row['dn'],
               message=msg, domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok(message=msg)
    except Exception as e:
        return api_error(e, 'user', 'toggle_user', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:uid>/unlock', methods=['POST'])
@login_required
def unlock(uid):
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return fail('用户不存在，请刷新列表', status=404)
    try:
        d = guard_write(row['domain_id'])
        L.set_unlock(d, row['dn'])
        sync_task.refresh_user_by_dn(d, row['dn'])
        log_op('user', 'unlock_user', target=row['dn'], message='账号已解锁',
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok(message='账号已解锁')
    except Exception as e:
        return api_error(e, 'user', 'unlock_user', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:uid>/reset-password', methods=['POST'])
@login_required
def reset_password(uid):
    """高危：重置密码。强制二次确认 + 不建议在日志中记录明文密码。"""
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return fail('用户不存在，请刷新列表', status=404)
    try:
        require_confirm()
        d = guard_write(row['domain_id'])
        pwd = request.form.get('password') or ''
        if request.form.get('password_mode') == 'random' or not pwd:
            pwd = generate_password()
        err = password_strength_error(pwd)
        if err:
            return fail(err)
        must_change = request.form.get('must_change', '1') in ('1', 'on', 'true')
        L.reset_password(d, row['dn'], pwd, must_change=must_change, unlock=True)
        sync_task.refresh_user_by_dn(d, row['dn'])
        log_op('user', 'reset_password', target=row['dn'], result='success',
               detail='密码已重置，账号同步解锁（日志不记录明文密码）',
               message='重置密码成功', domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok({'password': pwd}, '密码已重置')
    except Exception as e:
        return api_error(e, 'user', 'reset_password', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:uid>/move', methods=['POST'])
@login_required
def move(uid):
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return fail('用户不存在，请刷新列表', status=404)
    try:
        d = guard_write(row['domain_id'])
        target_ou = request.form.get('target_ou', '').strip()
        new_dn = L.move_user(d, row['dn'], target_ou)
        sync_task.refresh_user_by_dn(d, new_dn, old_dn=row['dn'])
        log_op('user', 'move_user', target=row['dn'], detail=f'移动到 {target_ou}', message='用户已移动',
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok({'dn': new_dn}, '用户已移动到目标 OU')
    except Exception as e:
        return api_error(e, 'user', 'move_user', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:uid>/groups', methods=['POST'])
@login_required
def groups(uid):
    """加组 / 移除组。"""
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return fail('用户不存在，请刷新列表', status=404)
    try:
        d = guard_write(row['domain_id'])
        group_dn = request.form.get('group_dn', '')
        action = request.form.get('action', 'add')
        if not group_dn:
            return fail('请选择用户组')
        if action == 'add':
            L.add_group_members(d, group_dn, [row['dn']])
            msg = '已加入用户组'
        else:
            L.remove_group_members(d, group_dn, [row['dn']])
            msg = '已从用户组移除'
        log_op('group', f'{action}_member', target=f'{row["dn"]} -> {group_dn}', message=msg,
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok(message=msg)
    except Exception as e:
        return api_error(e, 'group', 'member_change', target=row['dn'], domain_id=row['domain_id'])


@bp.route('/<int:uid>/delete', methods=['POST'])
@permission_required('user', 'delete')
@login_required
def delete(uid):
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return fail('用户不存在，请刷新列表', status=404)
    try:
        require_confirm()
        if (row['sam_account_name'] or '').lower() in ('administrator', 'krbtgt', 'guest') and \
                not request.form.get('force') == '1':
            return fail('该账号为域内置关键账号，禁止删除（如确需操作请由域管理员直接处理）')
        d = guard_write(row['domain_id'])
        # 软删除：先快照进回收站（含实时组关系），再物理删除 AD
        snapshot = {k: row[k] for k in row.keys()}
        snapshot['groups'] = _user_member_of(d, row['dn'])
        recycle_bin.add('user', d.id, row['sam_account_name'], row['dn'], snapshot, operator_name())
        L.delete_user(d, row['dn'])
        sync_task.delete_user_cache(d, row['dn'])
        log_op('user', 'delete_user', target=row['dn'], result='success',
               detail=f"登录名 {row['sam_account_name']}（已移入回收站，30 天内可还原）", message='删除用户成功',
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok(message='用户已删除（已移入回收站）')
    except Exception as e:
        return api_error(e, 'user', 'delete_user', target=row['dn'], domain_id=row['domain_id'])


def _user_member_of(d, dn: str) -> list:
    """读取用户所属组 DN 列表（删除前快照用，失败返回空不阻断）。"""
    try:
        conn = L.get_connection(d)
        if conn.search(dn, '(objectClass=*)', search_scope='BASE', attributes=['memberOf'], size_limit=1) and conn.entries:
            g = conn.entries[0]['memberOf'].value if 'memberOf' in conn.entries[0] else []
            return [g] if isinstance(g, str) else list(g or [])
    except Exception:
        pass
    return []


@bp.route('/<int:uid>/offboard', methods=['POST'])
@permission_required('user', 'offboard')
@login_required
@feature_required('offboard')
def offboard(uid):
    """离职一键处理：禁用 + 移除所有组 + 可选移动到离职 OU。"""
    t0 = time.time()
    row = db.query_one('SELECT * FROM ad_user_cache WHERE id=?', (uid,))
    if not row:
        return fail('用户不存在，请刷新列表', status=404)
    try:
        require_confirm()
        d = guard_write(row['domain_id'])
        offboard_ou = request.form.get('offboard_ou', '').strip()
        res = L.offboard_user(d, row['dn'], offboard_ou)
        sync_task.refresh_user_by_dn(d, res['dn'], old_dn=row['dn'])
        msg = '离职处理完成：账号已禁用'
        if res['groups_removed']:
            msg += f"，移除 {res['groups_removed']} 个组"
        if res.get('failed_groups'):
            msg += f"，{len(res['failed_groups'])} 个组移除失败"
        if offboard_ou:
            msg += '，已移入离职 OU'
        log_op('user', 'offboard_user', target=res['dn'], result='success',
               detail=f"移除组 {res['groups_removed']} 个" + (f"，失败 {res['failed_groups']}" if res['failed_groups'] else ''),
               message=msg, domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok({'dn': res['dn']}, msg)
    except Exception as e:
        return api_error(e, 'user', 'offboard_user', target=row['dn'], domain_id=row['domain_id'])


# ---------------------------------------------------------------- 批量
def _batch_rows():
    ids = request.form.getlist('ids[]') or request.form.getlist('ids')
    if not ids:
        raise ValueError('未选择任何用户')
    ids = [int(i) for i in ids if str(i).isdigit()]
    if len(ids) > config.BATCH_LIMIT:
        raise ValueError(f'单次批量操作上限 {config.BATCH_LIMIT} 条，请分批执行')
    marks = ','.join('?' * len(ids))
    return db.query(f'SELECT * FROM ad_user_cache WHERE id IN ({marks})', tuple(ids))


@bp.route('/batch', methods=['POST'])
@login_required
def batch():
    """
    批量操作：禁用/启用/移动/删除/加组。排队串行执行（全局写锁），逐条直连 AD。
    返回逐条结果，失败不影响其它对象。
    """
    t0 = time.time()
    action = request.form.get('action', '')
    try:
        rows = _batch_rows()
        if not rows:
            raise ValueError('所选用户已不在缓存中，请刷新列表')
        if action in ('delete', 'reset_password'):
            require_confirm()
        # 同一个域才能批量操作（跨域需分别执行，避免误操作）
        domain_ids = {r['domain_id'] for r in rows}
        if len(domain_ids) > 1:
            raise ValueError('批量操作仅支持同一域内的用户，请按域筛选后再执行')
        domain_id = domain_ids.pop()
        d = guard_write(domain_id)
        success, failed = [], []
        payload = request.form.get('target_ou', '') if action == 'move' else request.form.get('group_dn', '')
        batch_pwd = request.form.get('password', '')
        batch_field = request.form.get('field', '')
        batch_value = request.form.get('value', '')
        results = []
        with batch_lock(timeout=300):
            if action == 'move' and not payload:
                raise ValueError('请选择目标 OU')
            if action == 'add_group' and not payload:
                raise ValueError('请选择目标用户组')
            for r in rows:
                try:
                    if action == 'disable':
                        L.set_enabled(d, r['dn'], False)
                    elif action == 'enable':
                        L.set_enabled(d, r['dn'], True)
                    elif action == 'delete':
                        if (r['sam_account_name'] or '').lower() in ('administrator', 'krbtgt'):
                            raise L.ADError('内置关键账号禁止批量删除')
                        L.delete_user(d, r['dn'])
                    elif action == 'move':
                        new_dn = L.move_user(d, r['dn'], payload)
                        sync_task.refresh_user_by_dn(d, new_dn, old_dn=r['dn'])
                        success.append(r['sam_account_name'])
                        continue
                    elif action == 'add_group':
                        L.add_group_members(d, payload, [r['dn']])
                        success.append(r['sam_account_name'])
                        continue
                    elif action == 'unlock':
                        L.set_unlock(d, r['dn'])
                    elif action == 'reset_password':
                        if not batch_pwd:
                            raise ValueError('请填写新密码')
                        pe = password_strength_error(batch_pwd)
                        if pe:
                            raise ValueError(pe)
                        L.reset_password(d, r['dn'], batch_pwd, must_change=True)
                    elif action == 'update_field':
                        if batch_field not in ('department', 'title', 'company', 'description'):
                            raise ValueError(f'不支持的批量修改字段：{batch_field}')
                        L.update_user(d, r['dn'], {batch_field: batch_value})
                    else:
                        raise ValueError(f'不支持的批量操作：{action}')
                    if action == 'delete':
                        sync_task.delete_user_cache(d, r['dn'])
                    else:
                        sync_task.refresh_user_by_dn(d, r['dn'])
                    success.append(r['sam_account_name'])
                except Exception as e:
                    msg = e.message if isinstance(e, L.ADError) else str(e)
                    failed.append({'sam': r['sam_account_name'], 'error': msg})
        action_name = {'disable': '批量禁用', 'enable': '批量启用', 'delete': '批量删除',
                       'move': '批量移动', 'add_group': '批量加组', 'unlock': '批量解锁',
                       'reset_password': '批量重置密码', 'update_field': '批量修改属性'}.get(action, action)
        msg = f'{action_name}完成：成功 {len(success)} 个' + (f'，失败 {len(failed)} 个' if failed else '')
        log_op('user', f'batch_{action}', target=f'共 {len(rows)} 个用户', result='success' if not failed else 'failed',
               detail=f'成功：{", ".join(success[:50])}；失败：{failed[:20]}',
               message=msg, domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok({'success': success, 'failed': failed}, msg)
    except Exception as e:
        return api_error(e, 'user', f'batch_{action}', target='批量操作')


# ---------------------------------------------------------------- 导入导出
@bp.route('/import', methods=['GET'])
@login_required
def import_page():
    domains = L.load_domains(only_enabled=True)
    return render_template('user_import.html', domains=domains)


@bp.route('/import/template')
@login_required
def import_template():
    data = excel_service.user_import_template()
    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name='AD用户导入模板.xlsx',
                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


@bp.route('/import/validate', methods=['POST'])
@login_required
def import_validate():
    try:
        f = request.files.get('file')
        if not f or not f.filename:
            return fail('请选择 Excel 文件（.xlsx）')
        if not f.filename.lower().endswith('.xlsx'):
            return fail('仅支持 .xlsx 格式（可用模板另存为）')
        domain_ids = [int(x) for x in request.form.getlist('domain_ids') if str(x).isdigit()]
        if not domain_ids:
            return fail('请选择导入目标域')
        for did in domain_ids:
            L.get_domain(did, only_enabled=True)
        content = f.read()
        if len(content) > 20 * 1024 * 1024:
            return fail('文件过大（上限 20MB）')
        res = excel_service.validate_import(content, domain_ids)
        dm = L.domain_map()
        # 预览：返回可导入用户的关键字段（不含密码，最多 200 条，防大文件撑爆响应）
        preview = [{
            'row': v.get('row', ''),
            'sam_account_name': v.get('sam_account_name', ''),
            'display_name': v.get('display_name', ''),
            'department': v.get('department', ''),
            'title': v.get('title', ''),
            'mail': v.get('mail', ''),
            'ou': (v.get('ou_dn') or '').split(',')[0][3:] if v.get('ou_dn') else '',
        } for v in res['valid'][:200]]
        return ok({'total': res['total'], 'valid': len(res['valid']), 'errors': res['errors'],
                   'preview': preview, 'preview_total': len(res['valid']),
                   'domains': [dm[i].domain_name for i in domain_ids if i in dm],
                   'token': _cache_import(res['valid'], domain_ids, res['errors'])},
                  f"校验完成：可导入 {len(res['valid'])} 条，异常 {len(res['errors'])} 条")
    except Exception as e:
        return api_error(e, 'user', 'import_validate')


_import_cache = {}


def _cache_import(valid: list, domain_ids: list, errors: list = None) -> str:
    import uuid
    token = uuid.uuid4().hex
    _import_cache[token] = {'rows': valid, 'domains': domain_ids, 'errors': errors or [], 'ts': time.time()}
    # 只保留最近 20 个，防止内存增长
    for k in sorted(_import_cache, key=lambda x: _import_cache[x]['ts'])[:-20]:
        _import_cache.pop(k, None)
    return token


@bp.route('/import/errors/export', methods=['POST'])
@login_required
def import_errors_export():
    """导出校验失败的错误明细（Excel），便于离线修正后重传。"""
    try:
        token = request.form.get('token', '')
        item = _import_cache.get(token)
        if not item:
            return fail('校验结果已失效，请重新上传校验')
        errors = item.get('errors', [])
        if not errors:
            return fail('没有可导出的错误记录')
        data = excel_service.export_import_errors(errors)
        return send_file(io.BytesIO(data), as_attachment=True,
                         download_name=f'导入错误明细_{time.strftime("%Y%m%d_%H%M%S")}.xlsx',
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as e:
        return api_error(e, 'user', 'import_errors_export')


@bp.route('/import/run', methods=['POST'])
@login_required
def import_run():
    t0 = time.time()
    try:
        token = request.form.get('token', '')
        item = _import_cache.get(token)
        if not item:
            return fail('校验结果已失效，请重新上传校验')
        if time.time() - item['ts'] > 3600:
            _import_cache.pop(token, None)
            return fail('校验结果已过期（超过 1 小时），请重新上传')
        require_confirm()
        # 单域用户上限硬限制：导入会向每个目标域各新增 len(rows) 个用户
        for did in item['domains']:
            _check_max_users(did, len(item['rows']))
        res = excel_service.run_import(item['rows'], item['domains'], operator_name(), client_ip())
        _import_cache.pop(token, None)
        log_op('user', 'import_users', target=f'共 {len(item["rows"])} 行',
               result='success' if not res['failed'] else 'failed',
               message=f'导入完成：成功 {len(res["success"])} 条，失败 {len(res["failed"])} 条',
               duration_ms=int((time.time() - t0) * 1000))
        return ok(res, f'导入完成：成功 {len(res["success"])} 条，失败 {len(res["failed"])} 条')
    except Exception as e:
        return api_error(e, 'user', 'import_users')


@bp.route('/export')
@permission_required('user', 'export')
@login_required
def export():
    try:
        scope = request.args.get('scope', 'current')
        if scope == 'all':
            domain_ids = [d.id for d in L.load_domains()]
        else:
            did = int_arg('domain_id')
            if not did:
                domains = L.load_domains()
                if len(domains) == 1:
                    did = domains[0].id
                else:
                    return fail('请选择要导出的域')
            domain_ids = [did]
        f = _filters()
        f.pop('domain_id', None)
        # 扩展筛选：注册时间范围 / 职位角色 / 锁定状态（供选择性导出）
        f['created_from'] = request.args.get('created_from', '').strip()
        f['created_to'] = request.args.get('created_to', '').strip()
        f['title'] = request.args.get('title', '').strip()
        f['locked'] = request.args.get('locked', 'all')
        # 选择性导出（按条件）为高级功能：标准版仅支持导出全部/当前筛选结果
        from modules import license as lic
        selective = any([f['created_from'], f['created_to'], f['title'],
                         str(f['locked']) not in ('', 'all')])
        if selective and not lic.feature_allowed('selective_export'):
            return fail('当前授权版本不含「选择性导出（按条件）」功能，仅支持导出全部/当前筛选结果，'
                        '请升级到专业版或企业版', code='featureLocked')
        data = excel_service.export_users(domain_ids, f)
        log_op('user', 'export_users', target=f'{len(domain_ids)} 个域',
               message='导出用户台账', domain_id=domain_ids[0] if len(domain_ids) == 1 else None)
        name = f"AD用户台账_{time.strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(io.BytesIO(data), as_attachment=True, download_name=name,
                         mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as e:
        return api_error(e, 'user', 'export_users')
