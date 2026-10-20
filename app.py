# -*- coding: utf-8 -*-
"""
AD域Web管理系统 - 应用入口
================================
启动顺序（顺序很重要）：
1. 初始化日志 → 2. 初始化数据库（WAL）→ 3. 默认账号/调试域 → 4. 注册路由
5. 启动后台任务 worker → 6. 启动调度器 → 7. 首启自动全量同步（后台线程，不阻塞启动）

生产部署：waitress（Windows 原生支持，无需 gunicorn）。
    python app.py --host 0.0.0.0 --port 8000 --prod
"""
import argparse
import os
import sys
import threading

from flask import Flask, render_template, request, g, session, jsonify

import config
from modules.applog import setup_logging, get_logger
from modules import db
from modules import auth_service, domain_service
from modules import scheduler as sched
from modules import task_queue

log = get_logger('app')


def create_app() -> Flask:
    setup_logging()
    db.init_db()
    auth_service.ensure_default_admin()
    from modules import rbac
    rbac.ensure_builtin_roles()
    if config.ENABLE_DEBUG_DOMAIN:
        domain_service.ensure_debug_domain()
    from modules import license as license_module
    license_module.ensure_trial()

    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config.update(
        SECRET_KEY=_get_secret_key(),
        SESSION_COOKIE_NAME='adm_session',       # 与许可服务器(lic_session)隔离，避免 localhost 下 cookie 互相覆盖
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=config.SESSION_TIMEOUT_MINUTES * 60,
        MAX_CONTENT_LENGTH=32 * 1024 * 1024,          # 上传上限 32MB
        JSON_AS_ASCII=False,
        TEMPLATES_AUTO_RELOAD=False,
    )
    app.json.ensure_ascii = False

    from routes import (auth, dashboard, domain, trust, user, ou, group, computer, log as log_route,
                        config as config_route, alerts, recycle, license as license_route, health,
                        security)
    for bp in (auth.bp, dashboard.bp, domain.bp, trust.bp, user.bp, ou.bp, group.bp,
               computer.bp, log_route.bp, config_route.bp, alerts.bp, recycle.bp, license_route.bp,
               health.bp, security.bp):
        app.register_blueprint(bp)

    @app.context_processor
    def inject_license_features():
        from modules import license as lic
        from modules import rbac
        from routes.common import current_user
        u = getattr(g, 'user', None) or current_user()
        role = rbac.user_role(u)
        return {'lic_features': lic.features(),
                'rbac_perms': (role or {}).get('permissions', {})}

    _register_middleware(app)
    _register_error_handlers(app)

    task_queue.ensure_worker()
    sched.init_scheduler()

    # 首启：后台做一次全量同步（不阻塞 Web 启动）
    if db.scalar('SELECT COUNT(*) FROM ad_user_cache', (), 0) == 0:
        threading.Thread(target=_bootstrap_sync, name='bootstrap-sync', daemon=True).start()
    return app


def _get_secret_key() -> str:
    if config.SECRET_KEY:
        return config.SECRET_KEY
    path = os.path.join(config.DATA_DIR, '.flask_secret')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            v = f.read().strip()
        if v:
            return v
    import secrets
    v = secrets.token_hex(32)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(v)
    return v


def _bootstrap_sync():
    from modules import sync_task
    try:
        log.info('首启：开始初始化同步（逐域串行）')
        for res in sync_task.sync_all('full', operator='system'):
            log.info('初始化同步 %s: %s', res.get('domain'), res.get('message'))
    except Exception as e:
        log.warning('初始化同步失败：%s', e)


def _register_middleware(app: Flask):
    from routes.common import current_user

    @app.before_request
    def load_user():
        if request.endpoint in (None, 'static', 'auth.login'):
            return
        current_user()
        # 页面顶栏需要域列表与当前域
        if not request.path.startswith('/api/') and request.headers.get('X-Requested-With') != 'XMLHttpRequest':
            from modules import ad_ldap as L
            g.domains = L.load_domains()

    @app.context_processor
    def inject_globals():
        from modules import ad_ldap as L
        from routes.common import current_user
        u = getattr(g, 'user', None) or current_user()
        role_names = auth_service.ROLE_NAMES
        cur = None
        try:
            raw = request.values.get('domain_id')
            if raw and str(raw).isdigit():
                cur = L.get_domain(int(raw))
        except Exception:
            cur = None
        return {
            'current_user': u, 'role_names': role_names, 'app_name': config.APP_NAME,
            'nav_domains': getattr(g, 'domains', None) or [], 'current_domain': cur,
            'debug_domain': config.DEBUG_DOMAIN if config.ENABLE_DEBUG_DOMAIN else None,
            'session_timeout_minutes': auth_service.session_timeout_minutes(),
            'version': config.APP_VERSION,
        }

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
        resp.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
        resp.headers.setdefault('Referrer-Policy', 'same-origin')
        return resp


def _register_error_handlers(app: Flask):
    from modules import ad_ldap as L

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'ok': False, 'message': '接口不存在'}), 404
        return render_template('error.html', code=404, message='页面不存在'), 404

    @app.errorhandler(413)
    def too_large(e):
        return jsonify({'ok': False, 'message': '上传文件过大（上限 32MB）'}), 413

    @app.errorhandler(500)
    def server_error(e):
        log.exception('未处理的服务器异常')
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'ok': False, 'message': '服务器内部错误，请查看 logs/app.log'}), 500
        return render_template('error.html', code=500, message='服务器内部错误，请查看日志文件'), 500

    @app.errorhandler(L.ADError)
    def ad_error(e):
        code = 503 if isinstance(e, L.ADUnavailable) else 400
        if request.path.startswith('/api/') or request.is_json:
            return jsonify({'ok': False, 'message': e.message, 'code': e.code}), code
        return render_template('error.html', code=code, message=e.message), code


app = create_app()


def _fix_console_encoding():
    """
    控制台中文显示修正：
    Windows 控制台默认代码页为 936(GBK)/437，而 Python 3 输出 UTF-8 时会乱码。
    这里把控制台输入输出代码页切到 UTF-8（65001），并让标准流使用 UTF-8；
    PyInstaller 打包后同样生效。失败时静默忽略，不影响服务。
    """
    if os.name != 'nt':
        return
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass
    for stream_name in ('stdout', 'stderr'):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            # windowed 打包（console=False 无控制台）：stdout 为 None，print 会崩；
            # 重定向到空设备保证服务安装等 CLI 子命令正常退出
            try:
                setattr(sys, stream_name, open(os.devnull, 'w', encoding='utf-8', errors='replace'))
            except Exception:
                pass
            continue
        try:
            if hasattr(stream, 'reconfigure'):
                stream.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass


def main():
    _fix_console_encoding()
    parser = argparse.ArgumentParser(description='AD域控管理系统')
    parser.add_argument('--host', default=config.SERVER_HOST)
    parser.add_argument('--port', type=int, default=config.SERVER_PORT)
    parser.add_argument('--prod', action='store_true', help='使用 waitress 多线程服务（生产）')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--install-service', action='store_true', help='安装为 Windows 服务（开机自启）')
    parser.add_argument('--remove-service', action='store_true', help='删除 Windows 服务')
    parser.add_argument('--run-service', action='store_true', help='作为 Windows 服务运行（由 SCM 调用）')
    args = parser.parse_args()

    # ---- Windows 服务子命令（仅在 Windows 上生效）----
    if args.install_service or args.remove_service or args.run_service:
        if os.name != 'nt':
            print('Windows 服务仅支持 Windows 平台')
            return
        try:
            from win_service import install_service, remove_service, run_service
        except ImportError as e:
            print('缺少 pywin32 依赖，无法使用 Windows 服务：', e)
            return
        if args.run_service:
            run_service()
        elif args.install_service:
            install_service()
        elif args.remove_service:
            remove_service()
        return

    url = f'http://{"127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host}:{args.port}'
    log.info('=' * 60)
    log.info('%s v%s 启动中', config.APP_NAME, config.APP_VERSION)
    log.info('访问地址：%s   默认账号：%s', url, config.DEFAULT_ADMIN_USER)
    log.info('数据目录：%s', config.DATA_DIR)
    if config.ENABLE_DEBUG_DOMAIN:
        log.info('调试域：%s @ %s', config.DEBUG_DOMAIN['domain_name'], config.DEBUG_DOMAIN['dc_host'])
    log.info('=' * 60)

    if args.prod:
        try:
            from waitress import serve
            serve(app, host=args.host, port=args.port, threads=8, ident=None)
            return
        except ImportError:
            log.warning('未安装 waitress，回退到 Flask 内置服务器（不建议生产使用）')
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True, use_reloader=False)


if __name__ == '__main__':
    # PyInstaller 打包后多进程/服务场景需要（本应用用线程，此处为保险）
    try:
        import multiprocessing
        multiprocessing.freeze_support()
    except Exception:
        pass
    try:
        main()
    except KeyboardInterrupt:
        log.info('收到退出信号')
    finally:
        sched.shutdown()
