# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 单文件（onefile）打包配置 —— AD 域控管理系统便携版。"""
import os
import sys

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(SPEC)), '..'))
sys.path.insert(0, ROOT)

APP_NAME = 'AD域控管理系统'

hiddenimports = []
for pkg in ('ldap3', 'winrm', 'apscheduler', 'openpyxl', 'cryptography',
            'flask', 'jinja2', 'werkzeug', 'waitress', 'requests',
            'ldap3.core', 'ldap3.operation', 'ldap3.protocol',
            'ldap3.protocol.microsoft', 'ldap3.extend', 'ldap3.extend.microsoft'):
    hiddenimports += collect_submodules(pkg)

hiddenimports += [
    'modules.ad_ldap', 'modules.ad_trust', 'modules.sync_task', 'modules.log_service',
    'modules.excel_service', 'modules.task_queue', 'modules.scheduler', 'modules.query_service',
    'modules.domain_service', 'modules.auth_service', 'modules.security',
    'modules.license', 'modules.recycle_bin', 'modules.rbac', 'modules.alert_notify',
    'modules.ad_health', 'modules.security_center', 'modules.backup',
    'win_service',
    'win32service', 'win32serviceutil', 'win32event', 'servicemanager', 'win32timezone',
    'routes.auth', 'routes.dashboard', 'routes.domain', 'routes.trust', 'routes.user',
    'routes.ou', 'routes.group', 'routes.computer', 'routes.log', 'routes.config',
    'routes.common', 'routes.license', 'routes.alerts', 'routes.recycle',
    'routes.health', 'routes.security',
]

datas = [
    (os.path.join(ROOT, 'templates'), 'templates'),
    (os.path.join(ROOT, 'static'), 'static'),
]
for pkg in ('openpyxl', 'cryptography', 'waitress'):
    try:
        datas += collect_data_files(pkg)
    except Exception:
        pass

block_cipher = None

a = Analysis(
    [os.path.join(ROOT, 'app.py')],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'scipy', 'PIL', 'test', 'unittest',
              'pydoc_data', 'sqlite3.test'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

icon_path = os.path.join(ROOT, 'deploy', 'adm.ico')
if not os.path.exists(icon_path):
    icon_path = None

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,            # 无黑框：便携版双击后台运行，日志见 exe 同级 logs\app.log
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)
