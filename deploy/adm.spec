# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller 打包配置 —— AD 域控管理系统（Windows 便携版）
=========================================================
用法（在项目根目录执行）：
    pip install -r requirements.txt pyinstaller
    pyinstaller deploy/adm.spec --noconfirm --clean

产物：
    dist/AD域控管理系统/AD域控管理系统.exe        ← 单目录版（启动快，推荐）
    加 --onefile 变体见 deploy/build_portable.bat

关键点：
1. static/ 与 templates/ 必须随包携带（onedir 模式打包进 _internal 目录）；
2. 数据目录（database/ logs/）不打包，运行时由 config._app_root() 落在 exe 同级，
   安装包场景通过 ADM_WORK_DIR 指向 %ProgramData%；
3. ldap3 / winrm 有大量动态导入，需要显式 hiddenimports；
4. cryptography 的 Rust 后端需要 collect_submodules 收集。
"""
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

# 本项目的动态导入（模块内延迟 import）
hiddenimports += [
    'modules.ad_ldap', 'modules.ad_trust', 'modules.sync_task', 'modules.log_service',
    'modules.excel_service', 'modules.task_queue', 'modules.scheduler', 'modules.query_service',
    'modules.domain_service', 'modules.auth_service', 'modules.security',
    'modules.license', 'modules.recycle_bin',
    'routes.auth', 'routes.dashboard', 'routes.domain', 'routes.trust', 'routes.user',
    'routes.ou', 'routes.group', 'routes.computer', 'routes.log', 'routes.config',
    'routes.common', 'routes.license', 'routes.alerts', 'routes.recycle',
]

datas = [
    (os.path.join(ROOT, 'templates'), 'templates'),
    (os.path.join(ROOT, 'static'), 'static'),
]
# cryptography / openpyxl 可能需要的数据文件
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
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                      # UPX 压缩极易触发杀软误报，默认关闭
    console=True,                   # 桌面快捷方式用 --win-console 隐藏；Web 服务需保留控制台便于排错
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=APP_NAME,
)
