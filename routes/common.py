# -*- coding: utf-8 -*-
"""
路由公共工具
================================
- login_required / admin_required 装饰器
- 统一 JSON 返回 {ok, message, data}
- 域故障隔离：写操作前统一走 guard_write(domain_id)
- 批量操作锁：acquire_batch_lock
"""
import functools
import time
import re
from datetime import datetime

from flask import session, request, redirect, url_for, jsonify, g, flash

import config
from modules import db
from modules import ad_ldap as L
from modules import log_service
from modules.applog import get_logger
from modules.security import verify_password

log = get_logger('routes')


# ---------------------------------------------------------------- 认证
def current_user():
    if getattr(g, 'user', None):
        return g.user
    uid = session.get('uid')
    if not uid:
        return None
    row = db.query_one('SELECT * FROM sys_user WHERE id=? AND status=1', (uid,))
    if not row:
        session.clear()
        return None
    # 账号有效期校验：过期立即失效
    if row['account_expires'] and row['account_expires'] < datetime.now().strftime('%Y-%m-%d %H:%M:%S'):
        session.clear()
        return None
    from modules import auth_service
    # 单账号单会话互踢：令牌被更新的登录覆盖 → 本会话失效（禁止并发时生效）
    if not auth_service.is_login_token_valid(uid, session.get('login_token')):
        session.clear()
        return None
    # 无操作超时（滑动过期；0 = 永不超时）
    timeout = auth_service.session_timeout_minutes()
    if timeout > 0:
        last = session.get('ts', 0)
        if time.time() - float(last or 0) > timeout * 60:
            session.clear()
            return None
    session['ts'] = time.time()
    g.user = row
    return row


def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json \
                    or request.path.startswith('/api/'):
                return jsonify({'ok': False, 'message': '登录已过期，请重新登录', 'code': 'auth'}), 401
            return redirect(url_for('auth.login', next=request.path))
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @functools.wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if (g.user['role'] if getattr(g, 'user', None) else None) != 'super_admin':
            if wants_json():
                return jsonify({'ok': False, 'message': '该操作仅超级管理员可执行'}), 403
            flash('该操作仅超级管理员可执行', 'danger')
            return redirect(request.referrer or url_for('dashboard.index'))
        return fn(*a, **kw)
    return wrapper


def permission_required(module: str, action: str = 'view'):
    """RBAC 权限装饰器：当前用户角色缺少该模块/操作时拦截。超级管理员恒放行。"""
    def deco(fn):
        @functools.wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            from modules import rbac
            if not rbac.has_permission(current_user(), module, action):
                msg = '无权限执行此操作'
                if wants_json():
                    return jsonify({'ok': False, 'message': msg}), 403
                flash(msg, 'danger')
                return redirect(request.referrer or url_for('dashboard.index'))
            return fn(*a, **kw)
        return wrapper
    return deco


def scoped_domains():
    """当前用户按数据范围可访问的域列表（None 语义已在 rbac 内处理）。"""
    from modules import rbac
    return rbac.visible_domains(current_user())


def feature_required(name: str):
    """高级功能权限装饰器：当前授权版本不含该功能时拦截（试用/未激活按 enterprise 全开）。"""
    def deco(fn):
        @functools.wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            from modules import license as lic
            if not lic.feature_allowed(name):
                msg = '当前授权版本不含此功能，请升级到更高版本'
                if wants_json():
                    return jsonify({'ok': False, 'message': msg}), 403
                flash(msg, 'danger')
                return redirect(url_for('dashboard.index'))
            return fn(*a, **kw)
        return wrapper
    return deco


def feature_guard(name: str):
    """blueprint 级守卫函数：bp.before_request(feature_guard('xxx')) 对整个模块拦截。"""
    def guard():
        if not getattr(g, 'user', None):
            return None  # 未登录，交给 login_required 处理
        from modules import license as lic
        if not lic.feature_allowed(name):
            msg = '当前授权版本不含此功能，请升级到更高版本'
            if wants_json():
                return jsonify({'ok': False, 'message': msg}), 403
            flash(msg, 'danger')
            return redirect(url_for('dashboard.index'))
        return None
    return guard


def wants_json() -> bool:
    return (request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            or request.is_json or request.path.startswith('/api/')
            or request.headers.get('Accept', '').startswith('application/json'))


def ok(data=None, message='操作成功', **extra):
    payload = {'ok': True, 'message': message, 'data': data}
    payload.update(extra)
    return jsonify(payload)


def fail(message: str, code: str = '', status: int = 400, **extra):
    payload = {'ok': False, 'message': message, 'code': code}
    payload.update(extra)
    return jsonify(payload), status


def client_ip() -> str:
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or ''


def operator_name() -> str:
    u = getattr(g, 'user', None)
    return u['username'] if u else 'anonymous'


def log_op(module: str, action: str, target: str = '', detail: str = '', result: str = 'success',
           message: str = '', domain_id=None, domain_name: str = '', duration_ms: int = None):
    ip = client_ip()
    log_service.write(module, action, target=target, detail=detail, result=result, message=message,
                      operator=operator_name(), ip=ip, domain_id=domain_id,
                      domain_name=domain_name, duration_ms=duration_ms,
                      client_type=log_service.detect_client_type(request.headers.get('User-Agent', '')))


# ---------------------------------------------------------------- 域解析
def resolve_domain(required: bool = True):
    """
    从表单/查询参数解析 domain_id。
    required=True 且缺失/非法 → 抛 ValueError（由调用方转 400）。
    """
    raw = request.values.get('domain_id') or request.values.get('domain')
    if raw in (None, '', 'all'):
        if required:
            raise ValueError('请选择要操作的域')
        return None
    try:
        did = int(raw)
    except Exception:
        raise ValueError('域参数不合法')
    d = L.get_domain(did)
    return d


def guard_write(domain_id: int):
    """
    写操作守卫：授权有效 + 域必须启用且在线，否则抛异常（该域只读，其他域不受影响）。
    返回 DomainCtx。
    """
    from modules import license as lic
    if lic.get_state().get('status') == 'expired':
        raise L.ADError('试用期已结束，系统进入只读模式。请到「授权信息」导入许可文件激活后恢复写操作',
                        code='licenseExpired')
    d = L.get_domain(domain_id, only_enabled=True)
    if not d.enabled:
        raise L.DomainDisabled(f'域 {d.label} 已停用（只读）')
    L.require_online(d)
    return d


def api_error(e: Exception, module: str = '', action: str = '', target: str = '', domain_id=None):
    """统一异常 → JSON 错误 + 失败日志。"""
    if isinstance(e, L.ADError):
        msg, code = e.message, e.code
        log_op(module, action, target=target, result='failed', message=msg, domain_id=domain_id)
        return fail(msg, code=code)
    if isinstance(e, ValueError):
        log_op(module, action, target=target, result='failed', message=str(e), domain_id=domain_id)
        return fail(str(e), code='invalid')
    if isinstance(e, db.LockBusy):
        return fail(str(e), code='busy')
    log.exception('%s.%s 未预期异常', module, action)
    log_op(module, action, target=target, result='failed', message=f'系统异常：{e}', domain_id=domain_id)
    return fail(f'系统异常：{e}', code='internal', status=500)


# ---------------------------------------------------------------- 分页
def page_args(default_size: int = 20, max_size: int = 200):
    try:
        page = max(1, int(request.args.get('page', 1)))
    except Exception:
        page = 1
    try:
        size = int(request.args.get('page_size', default_size))
    except Exception:
        size = default_size
    size = max(1, min(size, max_size))
    return page, size


def int_arg(name: str, default=None):
    v = request.values.get(name)
    if v in (None, '', 'all'):
        return default
    try:
        return int(v)
    except Exception:
        return default


def bool_arg(name: str, default=None):
    v = request.values.get(name)
    if v in (None, ''):
        return default
    return str(v).lower() in ('1', 'true', 'on', 'yes')


DN_OU_RE = re.compile(r'^OU=', re.I)


def require_confirm():
    """高危操作二次确认：前端弹窗确认后提交 confirm=1，后端再校验一次。"""
    v = request.values.get('confirm')
    if str(v).lower() not in ('1', 'true', 'yes', 'on'):
        raise ValueError('高危操作需二次确认（请重新勾选确认后提交）')


def batch_lock(timeout: float = 300):
    return db.sync_lock('batch:write', ttl=1800, wait=timeout)


def dn_like(dn: str) -> str:
    """把 DN 转成可直接用于 `LIKE ? ESCAPE '\\'` 的字面前缀。

    DN 中的 `_` 是 SQL LIKE 的单字符通配符、`%` 是任意串通配符。如果直接
    拼 `'%,' + dn`，`OU=IT_01` 会误匹配 `OU=IT101`，在“判断子 OU / 迁移子树 /
    级联改名”这类结构性场景里会造成误删或误改。此处统一转义。
    """
    return db.dn_like(dn)


def dn_like_child(dn: str) -> str:
    """子对象方向的前缀（`dn + ',%'`），同样做转义。"""
    return db.dn_like_child(dn)

