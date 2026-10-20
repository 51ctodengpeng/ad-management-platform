# -*- coding: utf-8 -*-
"""登录 / 登出 / 修改密码"""
import time

from flask import Blueprint, render_template, request, redirect, url_for, session, g, jsonify

import config
from modules import auth_service, db
from modules import license as lic
from routes.common import login_required, ok, fail, client_ip, log_op, operator_name

bp = Blueprint('auth', __name__)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if session.get('uid'):
            return redirect(url_for('dashboard.index'))
        return render_template('login.html', app_name=config.APP_NAME,
                               debug_domain=config.DEBUG_DOMAIN if config.ENABLE_DEBUG_DOMAIN else None)

    username = request.form.get('username', '')
    password = request.form.get('password', '')
    ip = client_ip()
    user, err = auth_service.authenticate(username, password)
    if not user:
        log_op('auth', 'login', target=username, result='failed', message=err, domain_name='-')
        return fail(err, status=401)
    auth_service.touch_login(user['id'], ip)
    session.clear()
    session['uid'] = user['id']
    session['ts'] = time.time()
    session['login_token'] = auth_service.issue_login_token(user['id'])   # 单会话互踢令牌
    session.permanent = False
    log_op('auth', 'login', target=username, result='success',
           message=f'{auth_service.ROLE_NAMES.get(user["role"], user["role"])} 登录成功')
    return ok({'redirect': url_for('dashboard.index')}, '登录成功')


@bp.route('/logout', methods=['GET', 'POST'])
def logout():
    if session.get('uid'):
        auth_service.clear_login_token(session['uid'], session.get('login_token'))
        log_op('auth', 'logout', target=operator_name(), message='退出登录')
    session.clear()
    if request.method == 'POST':
        return ok({'redirect': url_for('auth.login')})
    return redirect(url_for('auth.login'))


@bp.route('/api/session')
@login_required
def session_info():
    """当前登录会话剩余有效时间（分钟）；-1 表示永不超时。供前端心跳/空闲检测使用。"""
    t = auth_service.session_timeout_minutes()
    if t <= 0:
        return ok({'never_expire': True, 'remaining_minutes': -1})
    last = session.get('ts', time.time())
    remain = max(0.0, t - (time.time() - float(last)) / 60.0)
    return ok({'never_expire': False, 'remaining_minutes': round(remain, 1)})


# ---------------------------------------------------------------- 密码恢复（忘记密码）
_RECOVERY_KEY = 'auth_fail:__recovery__'
_RECOVERY_MAX = 10           # 恢复接口连续失败次数上限
_RECOVERY_LOCK = 600         # 锁定时长（秒）


def _recovery_locked() -> tuple:
    """恢复接口防暴力：返回 (是否锁定, 提示)。连续失败 10 次锁 10 分钟。"""
    raw = db.get_setting(_RECOVERY_KEY)
    cnt, ts = 0, 0.0
    if raw:
        try:
            cnt, ts = raw.split('|')
            cnt, ts = int(cnt), float(ts)
        except Exception:
            cnt, ts = 0, 0.0
    if cnt >= _RECOVERY_MAX and time.time() - ts < _RECOVERY_LOCK:
        return True, '尝试次数过多，请 10 分钟后再试'
    return False, ''


def _recovery_fail() -> None:
    raw = db.get_setting(_RECOVERY_KEY)
    cnt, ts = 0, 0.0
    if raw:
        try:
            cnt, ts = raw.split('|')
            cnt, ts = int(cnt), float(ts)
        except Exception:
            cnt, ts = 0, 0.0
    db.set_setting(_RECOVERY_KEY, f'{cnt + 1}|{time.time()}')


def _recovery_ok() -> None:
    db.set_setting(_RECOVERY_KEY, '')


@bp.route('/forgot-password')
def forgot_password():
    return render_template('forgot_password.html', app_name=config.APP_NAME)


@bp.route('/api/recovery-options')
def recovery_options():
    """返回当前启用的密码恢复方式（供忘记密码页渲染）。"""
    return ok(auth_service.recovery_options())


@bp.route('/recovery/license', methods=['POST'])
def recovery_license():
    """导入许可重置密码：验签（+可选机器绑定）通过后重置超级管理员密码。"""
    try:
        locked, msg = _recovery_locked()
        if locked:
            return fail(msg)
        if not auth_service.recovery_allow_license():
            return fail('许可重置方式未启用，请联系管理员')
        raw = (request.form.get('text') or '').strip()
        if not raw:
            return fail('请粘贴许可文件内容')
        payload = lic._reverify(raw)
        if payload is None:
            _recovery_fail()
            return fail('许可无效：签名校验失败或已被篡改')
        bound = (payload.get('machine_id') or '').strip()
        if bound and bound != lic.machine_fingerprint():
            _recovery_fail()
            return fail('该许可绑定的机器与当前机器不匹配')
        new_pwd = request.form.get('password') or config.DEFAULT_ADMIN_PASSWORD
        username = auth_service.reset_admin_password(new_pwd)
        _recovery_ok()
        log_op('auth', 'recovery_reset', target=username, message='通过许可验签重置密码', domain_name='-')
        return ok({'username': username}, '密码已重置，请用新密码登录')
    except Exception as e:
        return fail(str(e))


@bp.route('/recovery/questions', methods=['POST'])
def recovery_questions():
    """密保问题重置密码：所有已设问题答对后重置超级管理员密码。"""
    try:
        locked, msg = _recovery_locked()
        if locked:
            return fail(msg)
        if not auth_service.recovery_allow_questions():
            return fail('密保问题方式未启用，请联系管理员')
        if not auth_service.has_security_questions():
            return fail('尚未设置密保问题，请使用其他方式或联系管理员')
        answers = {'1': request.form.get('a1', ''), '2': request.form.get('a2', ''),
                   '3': request.form.get('a3', '')}
        if not auth_service.verify_security_answers(answers):
            _recovery_fail()
            return fail('密保答案不正确')
        new_pwd = request.form.get('password') or config.DEFAULT_ADMIN_PASSWORD
        username = auth_service.reset_admin_password(new_pwd)
        _recovery_ok()
        log_op('auth', 'recovery_reset', target=username, message='通过密保问题重置密码', domain_name='-')
        return ok({'username': username}, '密码已重置，请用新密码登录')
    except Exception as e:
        return fail(str(e))


@bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html', u=g.user, role_names=auth_service.ROLE_NAMES,
                           session_timeout=config.SESSION_TIMEOUT_MINUTES)


@bp.route('/api/profile/password', methods=['POST'])
@login_required
def change_password():
    try:
        auth_service.change_password(g.user['id'], request.form.get('old_password', ''),
                                     request.form.get('new_password', ''))
        log_op('auth', 'change_password', target=g.user['username'], message='修改本人密码')
        return ok(message='密码已修改，请重新登录')
    except ValueError as e:
        return fail(str(e))
