# -*- coding: utf-8 -*-
"""部门 OU 管理（按域隔离）：树形展示、新增、编辑、删除、批量迁移用户"""
import time

from flask import Blueprint, render_template, request

from modules import db
from modules import ad_ldap as L
from modules import query_service as Q
from modules import sync_task
from modules import recycle_bin
from routes.common import (login_required, ok, fail, api_error, log_op, int_arg, guard_write,
                           require_confirm, batch_lock, dn_like, dn_like_child, operator_name)

bp = Blueprint('ou', __name__, url_prefix='/ous')


@bp.route('/')
@login_required
def index():
    domains = L.load_domains()
    domain_id = int_arg('domain_id') or (domains[0].id if domains else None)
    d = L.get_domain(domain_id) if domain_id else None
    tree = Q.ou_tree(domain_id, d.base_dn if d else '') if d else None
    # 每个 OU 的直属用户数已在缓存表维护
    return render_template('ous.html', domains=domains, d=d, tree=tree,
                           total_ou=db.scalar('SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=?',
                                              (domain_id,), 0) if domain_id else 0)


@bp.route('/api/tree')
@login_required
def api_tree():
    try:
        d = L.get_domain(int_arg('domain_id'))
        tree = Q.ou_tree(d.id, d.base_dn)
        return ok(tree)
    except Exception as e:
        return api_error(e, 'ou', 'tree')


@bp.route('/api/options')
@login_required
def api_options():
    """OU 下拉选项（用于移动用户、新建用户选择目标 OU）。"""
    d = L.get_domain(int_arg('domain_id'))
    rows = db.query('SELECT dn, name, depth FROM ad_ou_cache WHERE domain_id=? ORDER BY dn', (d.id,))
    opts = [{'dn': d.base_dn, 'name': '（域根）', 'depth': 0}]
    opts += [{'dn': r['dn'], 'name': r['name'], 'depth': r['depth']} for r in rows]
    return ok(opts)


@bp.route('/create', methods=['POST'])
@login_required
def create():
    t0 = time.time()
    domain_id = int_arg('domain_id')
    try:
        d = guard_write(domain_id)
        parent = request.form.get('parent_dn', '').strip() or d.base_dn
        name = request.form.get('name', '').strip()
        desc = request.form.get('description', '').strip()
        dn = L.create_ou(d, parent, name, desc)
        # 单条刷新缓存
        sync_task.upsert_ou(d, {'domain_id': d.id, 'dn': dn, 'name': name, 'parent_dn': parent,
                                'description': desc, 'depth': max(0, dn.count(',') - d.base_dn.count(',')),
                                'usn': 0, 'when_created': time.strftime('%Y-%m-%d %H:%M:%S')})
        log_op('ou', 'create_ou', target=dn, message='新增 OU 成功', domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok({'dn': dn}, f'OU「{name}」已创建')
    except Exception as e:
        return api_error(e, 'ou', 'create_ou', domain_id=domain_id)


@bp.route('/update', methods=['POST'])
@login_required
def update():
    t0 = time.time()
    domain_id = int_arg('domain_id')
    dn = request.form.get('dn', '')
    try:
        d = guard_write(domain_id)
        new_dn = L.update_ou(d, dn, request.form.to_dict())
        if new_dn != dn:
            # 重命名：更新该 OU 及所有子对象缓存（ad_ou_cache 自身无 ou_dn 列）
            # 注意：SQLite 的 UPDATE 是逐行进行的，若先按 "%,old_dn" 更新子行，
            # 父行 dn == old_dn 不满足该条件会被漏掉；因此必须先精确命中自身，
            # 再按子树后缀匹配。LIKE 里的 _ / % 需转义，否则 DN 中下划线会误匹配。
            suffix_old = dn_like(dn)
            with db.tx(immediate=True) as c:
                for table in ('ad_ou_cache', 'ad_user_cache', 'ad_group_cache', 'ad_computer_cache'):
                    c.execute(f"UPDATE OR REPLACE {table} SET dn=? WHERE domain_id=? AND dn=?",
                              (new_dn, d.id, dn))
                    c.execute(f"UPDATE OR REPLACE {table} SET dn=REPLACE(dn, ?, ?) "
                              f"WHERE domain_id=? AND dn LIKE ? ESCAPE '\\'",
                              (dn, new_dn, d.id, suffix_old))
                for table in ('ad_user_cache', 'ad_group_cache', 'ad_computer_cache'):
                    c.execute(f"UPDATE {table} SET ou_dn=REPLACE(ou_dn, ?, ?) "
                              f"WHERE domain_id=? AND ou_dn LIKE ? ESCAPE '\\'",
                              (dn, new_dn, d.id, suffix_old))
                    c.execute(f"UPDATE {table} SET ou_dn=? WHERE domain_id=? AND ou_dn=?", (new_dn, d.id, dn))
                c.execute('UPDATE ad_ou_cache SET parent_dn=? WHERE domain_id=? AND parent_dn=?',
                          (new_dn, d.id, dn))
                c.execute('UPDATE ad_ou_cache SET name=? WHERE domain_id=? AND dn=?',
                          (request.form.get('name', '').strip() or None, d.id, new_dn))
        else:
            db.execute('UPDATE ad_ou_cache SET description=? WHERE domain_id=? AND dn=?',
                       (request.form.get('description', '').strip(), d.id, dn))
        if request.form.get('name') and new_dn == dn:
            db.execute('UPDATE ad_ou_cache SET name=? WHERE domain_id=? AND dn=?',
                       (request.form.get('name', '').strip(), d.id, dn))
        log_op('ou', 'update_ou', target=new_dn, message='编辑 OU 成功', domain_id=d.id, domain_name=d.label,
               duration_ms=int((time.time() - t0) * 1000))
        return ok({'dn': new_dn}, 'OU 已更新')
    except Exception as e:
        return api_error(e, 'ou', 'update_ou', target=dn, domain_id=domain_id)


@bp.route('/delete', methods=['POST'])
@login_required
def delete():
    t0 = time.time()
    domain_id = int_arg('domain_id')
    dn = request.form.get('dn', '')
    try:
        d = guard_write(domain_id)
        recursive = request.form.get('recursive') == '1'
        require_confirm()
        if dn.strip().lower() == d.base_dn.lower():
            return fail('不能删除域根节点')
        children = db.scalar(
            "SELECT COUNT(*) FROM ad_ou_cache WHERE domain_id=? AND (dn LIKE ? ESCAPE '\\' OR dn LIKE ? ESCAPE '\\')",
            (d.id, dn_like(dn), dn_like_child(dn)), 0)
        if children and not recursive:
            raise ValueError(f'该 OU 下仍有 {children} 个子 OU，请先迁移子对象，或勾选"递归删除"')
        # 软删除：快照进回收站（含子树统计），再物理删除
        ou_row = db.query_one('SELECT * FROM ad_ou_cache WHERE domain_id=? AND dn=?', (d.id, dn))
        if ou_row:
            snap = dict(ou_row)
            snap['children_count'] = children
            recycle_bin.add('ou', d.id, ou_row['name'], dn, snap, operator_name())
        deleted = L.delete_ou(d, dn, recursive=recursive)
        sync_task.delete_ou_cache(d, dn)
        log_op('ou', 'delete_ou', target=dn, result='success',
               detail=f'递归删除 {deleted} 个对象（已移入回收站）', message='删除 OU 成功',
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok(message=f'OU 已删除（含 {deleted} 个对象）')
    except Exception as e:
        return api_error(e, 'ou', 'delete_ou', target=dn, domain_id=domain_id)


@bp.route('/move-users', methods=['POST'])
@login_required
def move_users():
    """批量迁移用户（同域内跨 OU）。"""
    t0 = time.time()
    domain_id = int_arg('domain_id')
    try:
        d = guard_write(domain_id)
        source = request.form.get('source_dn', '')
        target = request.form.get('target_ou', '')
        if not target:
            raise ValueError('请选择目标 OU')
        rows = db.query("SELECT * FROM ad_user_cache WHERE domain_id=? AND (ou_dn=? OR ou_dn LIKE ? ESCAPE '\\')",
                        (d.id, source, dn_like(source)))
        if not rows:
            return fail('源 OU 下没有用户')
        ok_list, failed = [], []
        with batch_lock(timeout=300):
            for r in rows:
                try:
                    new_dn = L.move_user(d, r['dn'], target)
                    sync_task.refresh_user_by_dn(d, new_dn, old_dn=r['dn'])
                    ok_list.append(r['sam_account_name'])
                except Exception as e:
                    failed.append({'sam': r['sam_account_name'],
                                   'error': e.message if isinstance(e, L.ADError) else str(e)})
        msg = f'迁移完成：成功 {len(ok_list)} 个' + (f'，失败 {len(failed)} 个' if failed else '')
        log_op('ou', 'move_users', target=f'{source} -> {target}',
               result='success' if not failed else 'failed', detail=str(failed[:20]), message=msg,
               domain_id=d.id, domain_name=d.label, duration_ms=int((time.time() - t0) * 1000))
        return ok({'success': ok_list, 'failed': failed}, msg)
    except Exception as e:
        return api_error(e, 'ou', 'move_users', domain_id=domain_id)
