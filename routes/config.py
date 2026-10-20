# -*- coding: utf-8 -*-
"""系统设置：运维账号管理、定时任务状态、数据库状态"""
import io
import os
from datetime import datetime

from flask import Blueprint, render_template, request, send_file

import config
from modules import db
from modules import auth_service
from modules import scheduler
from modules import ad_ldap as L
from modules import alert_notify
from modules import rbac
from modules import backup
from modules.security import generate_password
from routes.common import (login_required, admin_required, ok, fail, api_error, log_op,
                           require_confirm, int_arg, operator_name)
from modules.applog import get_logger

bp = Blueprint('config', __name__, url_prefix='/config')
log = get_logger('config')


def _alert_cfg() -> dict:
    return {
        'smtp': alert_notify.get_smtp_config(),
        'policies': alert_notify.POLICIES,
        'state': alert_notify.get_policy_state(),
    }


@bp.route('/')
@login_required
@admin_required
def index():
    users = db.query('SELECT * FROM sys_user ORDER BY id')
    jobs = scheduler.get_jobs()
    wal = db.query_one('PRAGMA journal_mode')[0]
    size = os.path.getsize(config.DB_PATH) if os.path.exists(config.DB_PATH) else 0
    stats = {
        'db_size': size, 'journal_mode': wal,
        'users_cached': db.scalar('SELECT COUNT(*) FROM ad_user_cache', (), 0),
        'logs': db.scalar('SELECT COUNT(*) FROM ad_operation_log', (), 0),
        'domains': db.scalar('SELECT COUNT(*) FROM ad_domain_conf', (), 0),
        'trusts': db.scalar('SELECT COUNT(*) FROM ad_trust_cache', (), 0),
    }
    _roles = rbac.list_roles()
    return render_template('config.html', users=users, jobs=jobs, stats=stats,
                           role_names=auth_service.ROLE_NAMES, cfg=config,
                           roles=_roles,
                           role_map={r['key']: r['display_name'] for r in _roles},
                           now_str=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                           rbac_modules=rbac.MODULES, rbac_action_names=rbac.ACTION_NAMES,
                           all_domains=[{'id': d.id, 'name': d.name, 'domain_name': d.domain_name}
                                        for d in L.load_domains()],
                           session_cfg={
                               'timeout': auth_service.session_timeout_minutes(),
                               'allow_concurrent': auth_service.allow_concurrent_login(),
                               'choices': auth_service.SESSION_TIMEOUT_CHOICES,
                           },
                           login_cfg=auth_service.login_cfg())


@bp.route('/email-alert')
@login_required
@admin_required
def email_alert():
    """邮箱告警通知（独立页面，所有许可证版本生效）。"""
    return render_template('email_alert.html', alert_cfg=_alert_cfg())


@bp.route('/users/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    try:
        username = request.form.get('username', '').strip()
        pwd = request.form.get('password') or generate_password(12)
        uid = auth_service.create_user(username, pwd, request.form.get('display_name', ''),
                                       request.form.get('role', 'operator'))
        log_op('system', 'create_sys_user', target=username, message='新增系统账号')
        return ok({'id': uid, 'password': pwd}, f'账号 {username} 已创建')
    except Exception as e:
        return api_error(e, 'system', 'create_sys_user')


@bp.route('/users/<int:uid>/reset', methods=['POST'])
@login_required
@admin_required
def reset_user(uid):
    try:
        require_confirm()
        pwd = request.form.get('password') or generate_password(12)
        auth_service.reset_password(uid, pwd)
        row = db.query_one('SELECT username FROM sys_user WHERE id=?', (uid,))
        log_op('system', 'reset_sys_password', target=row['username'] if row else str(uid),
               message='重置系统账号密码')
        return ok({'password': pwd}, '密码已重置（日志不记录明文）')
    except Exception as e:
        return api_error(e, 'system', 'reset_sys_password')


@bp.route('/users/<int:uid>/update', methods=['POST'])
@login_required
@admin_required
def update_user(uid):
    """编辑运维账号：显示名 / 角色身份 / 账号有效期。"""
    try:
        row = db.query_one('SELECT * FROM sys_user WHERE id=?', (uid,))
        if not row:
            return fail('账号不存在', status=404)
        from flask import g
        display_name = request.form.get('display_name')
        role = request.form.get('role')
        expires = (request.form.get('account_expires') or '').strip()
        if expires:
            expires = expires.replace('T', ' ').strip()
            if len(expires) == 16:               # datetime-local: YYYY-MM-DD HH:MM
                expires += ':00'
        if uid == g.user['id'] and role and role != 'super_admin':
            return fail('不能修改自己的角色（防止降权后失去管理权限）')
        auth_service.update_user(uid, display_name=display_name, role=role, account_expires=expires)
        log_op('system', 'update_sys_user', target=row['username'], message='更新账号信息')
        return ok(message='账号信息已更新')
    except Exception as e:
        return api_error(e, 'system', 'update_sys_user')


@bp.route('/users/<int:uid>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(uid):
    try:
        from flask import g
        row = db.query_one('SELECT * FROM sys_user WHERE id=?', (uid,))
        if not row:
            return fail('账号不存在', status=404)
        if row['id'] == g.user['id']:
            return fail('不能停用当前登录账号')
        enabled = request.form.get('enabled', '0') in ('1', 'on', 'true')
        db.execute('UPDATE sys_user SET status=? WHERE id=?', (1 if enabled else 0, uid))
        log_op('system', 'toggle_sys_user', target=row['username'],
               message='启用账号' if enabled else '停用账号')
        return ok(message='账号已启用' if enabled else '账号已停用')
    except Exception as e:
        return api_error(e, 'system', 'toggle_sys_user')


@bp.route('/jobs')
@login_required
@admin_required
def jobs():
    return ok(scheduler.get_jobs())


@bp.route('/security/save', methods=['POST'])
@login_required
@admin_required
def save_security():
    """保存会话安全设置（登录超时 + 单账号并发登录开关）。对所有许可证类型生效。"""
    try:
        try:
            t = int(request.form.get('session_timeout_minutes', ''))
        except (TypeError, ValueError):
            t = auth_service.session_timeout_minutes()
        if t != 0 and t not in auth_service.SESSION_TIMEOUT_CHOICES:
            raise ValueError('会话超时时长不合法')
        allow = '1' if request.form.get('allow_concurrent_login') in ('1', 'on', 'true') else '0'
        db.set_setting('session_timeout_minutes', str(t))
        db.set_setting('allow_concurrent_login', allow)
        log_op('system', 'save_security', target='会话安全',
               message=f"超时 {'永不' if t == 0 else str(t) + ' 分钟'} / 并发 {'允许' if allow == '1' else '禁止'}")
        return ok(message='会话安全设置已保存')
    except Exception as e:
        return api_error(e, 'system', 'save_security')


@bp.route('/login/save', methods=['POST'])
@login_required
@admin_required
def save_login():
    """保存登录安全（失败锁定阈值/时长）+ 密码恢复方式（许可/密保）+ 密保问题。"""
    try:
        try:
            max_fail = int(request.form.get('login_max_fail', '5'))
        except (TypeError, ValueError):
            max_fail = 5
        try:
            lock_sec = int(request.form.get('login_lock_seconds', '300'))
        except (TypeError, ValueError):
            lock_sec = 300
        if not (3 <= max_fail <= 20):
            raise ValueError('登录失败锁定阈值需在 3~20 次之间')
        if not (60 <= lock_sec <= 3600):
            raise ValueError('锁定时长需在 60~3600 秒之间')

        allow_license = '1' if request.form.get('recovery_allow_license') in ('1', 'on', 'true') else '0'
        allow_questions = '1' if request.form.get('recovery_allow_questions') in ('1', 'on', 'true') else '0'

        db.set_setting('login_max_fail', str(max_fail))
        db.set_setting('login_lock_seconds', str(lock_sec))
        db.set_setting('recovery_allow_license', allow_license)
        db.set_setting('recovery_allow_questions', allow_questions)

        # 密保问题（3 槽位；答案留空 = 不修改该槽位）
        questions = []
        for i in range(1, 4):
            q = (request.form.get(f'q{i}') or '').strip()
            a = (request.form.get(f'a{i}') or '').strip()
            questions.append((q, a))
        auth_service.set_security_questions(questions)

        log_op('system', 'save_login', target='登录安全与密码恢复',
               message=f'失败锁定 {max_fail} 次/{lock_sec}s，恢复方式 许可={allow_license} 密保={allow_questions}')
        return ok(message='登录安全与密码恢复设置已保存')
    except Exception as e:
        return api_error(e, 'system', 'save_login')


@bp.route('/roles/save', methods=['POST'])
@login_required
@admin_required
def save_role():
    """创建/更新自定义角色（模块×操作权限矩阵 + 数据范围）。"""
    try:
        key = (request.form.get('key') or '').strip()
        display_name = (request.form.get('display_name') or '').strip()
        description = (request.form.get('description') or '').strip()
        scope_type = request.form.get('scope_type') or 'all'
        scope_domains = [int(x) for x in request.form.getlist('scope_domains') if str(x).isdigit()]

        permissions = {}
        for m, v in rbac.MODULES.items():
            acts = [a for a in v['actions'] if request.form.get(f'perm_{m}_{a}') in ('1', 'on', 'true')]
            if acts:
                permissions[m] = acts

        if key in ('super_admin', 'operator'):
            raise ValueError('内置角色不可修改')

        if rbac.get_role(key):
            rbac.update_role(key, display_name, description, permissions, scope_type, scope_domains)
            msg = '角色已更新'
        else:
            rbac.create_role(key, display_name, description, permissions, scope_type, scope_domains)
            msg = '角色已创建'
        log_op('system', 'save_role', target=key, message=msg)
        return ok(message=msg)
    except Exception as e:
        return api_error(e, 'system', 'save_role')


@bp.route('/roles/delete', methods=['POST'])
@login_required
@admin_required
def delete_role():
    try:
        require_confirm()
        key = (request.form.get('key') or '').strip()
        rbac.delete_role(key)
        log_op('system', 'delete_role', target=key, message='删除角色')
        return ok(message='角色已删除')
    except Exception as e:
        return api_error(e, 'system', 'delete_role')


@bp.route('/prune-tasks', methods=['POST'])
@login_required
@admin_required
def prune_tasks():
    try:
        n = db.execute("DELETE FROM task_queue WHERE status IN ('success','failed') "
                       "AND finished_at < datetime('now','localtime','-7 days')")
        return ok({'deleted': n}, f'已清理 {n} 条历史任务记录')
    except Exception as e:
        return api_error(e, 'system', 'prune_tasks')


@bp.route('/alert/save', methods=['POST'])
@login_required
@admin_required
def save_alert():
    """保存邮箱告警配置（SMTP + 策略勾选/阈值）。对所有许可证类型生效。"""
    try:
        enabled = request.form.get('mail_enabled') in ('1', 'on', 'true')
        host = (request.form.get('mail_host') or '').strip()
        try:
            port = int(request.form.get('mail_port') or 465)
        except (TypeError, ValueError):
            port = 465
        security_mode = (request.form.get('mail_security') or 'ssl').strip()
        username = (request.form.get('mail_username') or '').strip()
        sender = (request.form.get('mail_sender') or '').strip()
        password = request.form.get('mail_password') or ''
        recipients = (request.form.get('mail_recipients') or '').strip()

        if security_mode not in ('ssl', 'tls', 'none'):
            raise ValueError('安全协议不合法')
        if port < 1 or port > 65535:
            raise ValueError('SMTP 端口不合法')
        if enabled and (not host or not sender):
            raise ValueError('启用邮件告警必须填写 SMTP 主机与发件邮箱')

        # 解析策略：勾选 + 阈值
        policies = {}
        for p in alert_notify.POLICIES:
            key = p['key']
            en = request.form.get(f'policy_{key}_enabled') in ('1', 'on', 'true')
            thr = 0
            if p['threshold']:
                try:
                    thr = int(request.form.get(f'policy_{key}_threshold') or 0)
                except (TypeError, ValueError):
                    thr = p['threshold']
                if thr <= 0 or thr > 100:
                    thr = p['threshold']
            policies[key] = {'enabled': en, 'threshold': thr}

        alert_notify.save_smtp_config(enabled, host, port, security_mode,
                                      username, sender, password, recipients)
        alert_notify.save_policy_state(policies)
        log_op('system', 'save_alert', target='邮箱告警通知',
               message=f'SMTP {host}:{port}/{security_mode} 收件人 {len(recipients.split(";"))} 人 / '
                       f'启用策略 {sum(1 for v in policies.values() if v["enabled"])} 项')
        return ok(message='邮箱告警配置已保存')
    except Exception as e:
        return api_error(e, 'system', 'save_alert')


@bp.route('/alert/test', methods=['POST'])
@login_required
@admin_required
def test_alert():
    """发送测试邮件，验证 SMTP 配置。"""
    try:
        to = (request.form.get('recipients') or '').strip()
        ok_sent, err = alert_notify.test_email(to or None)
        if not ok_sent:
            return fail(err or '发送失败')
        log_op('system', 'test_alert', target='邮箱告警通知', message='发送测试告警邮件')
        return ok(message='测试邮件已发送，请查收')
    except Exception as e:
        return api_error(e, 'system', 'test_alert')


@bp.route('/backup')
@login_required
@admin_required
def download_backup():
    """打包下载系统备份（数据库快照 + 密钥 + 元数据）。"""
    try:
        data, manifest = backup.create_backup()
        st = manifest.get('stats', {})
        log_op('system', 'backup', target='系统备份',
               message=f"备份 {st.get('domains', 0)} 域 / {st.get('users', 0)} 用户缓存 / {st.get('logs', 0)} 条日志")
        fn = 'adm_backup_%s.zip' % datetime.now().strftime('%Y%m%d_%H%M%S')
        return send_file(io.BytesIO(data), mimetype='application/zip',
                         as_attachment=True, download_name=fn)
    except Exception as e:
        return api_error(e, 'system', 'backup')


@bp.route('/backup/restore', methods=['POST'])
@login_required
@admin_required
def restore_backup():
    """上传备份包并还原（校验 → 自动快照 → 在线覆盖 → 迁移补齐）。"""
    try:
        require_confirm()
        f = request.files.get('file')
        if not f:
            return fail('请选择备份文件', status=400)
        data = f.read()
        if len(data) > 200 * 1024 * 1024:
            return fail('备份文件过大（上限 200MB）', status=400)
        if len(data) < 100:
            return fail('备份文件无效', status=400)

        res = backup.restore_backup(data, operator=operator_name())

        log_op('system', 'restore_backup', target='系统还原',
               message=f"还原自 {res['backup_created_at']} 的备份；还原前快照 {res['pre_backup']}；"
                       f"密钥匹配={res['key_matched']}")
        if not res['key_matched']:
            return ok(res, '已还原，但密钥与库内凭据疑似不匹配，请确认密钥是否正确')
        return ok(res, res['message'])
    except Exception as e:
        return api_error(e, 'system', 'restore_backup')
