# -*- coding: utf-8 -*-
"""
Windows 服务包装
================================
将 Flask/Waitress Web 服务注册为 Windows 服务（pywin32），实现：
- 开机自启（SERVICE_AUTO_START）、无黑框后台运行、可在 services.msc 管理
- 安装版数据目录固定到 %ProgramData%\\AD域控管理系统（可写、非管理员也能运行）
- 便携版（双击 exe）数据仍在 exe 同级目录，两种模式互不影响

命令行（由 app.py 转发）：
  --install-service   安装并注册服务
  --remove-service    删除服务
  --run-service       作为服务运行（由 SCM 调用）
"""
import os
import sys
import threading
import time

import pywintypes
import servicemanager
import win32event
import win32service
import win32serviceutil

SERVICE_NAME = 'ADDomainManager'
DISPLAY_NAME = 'AD域控管理系统'
DESCRIPTION = 'AD域控管理系统 Web 服务（PowerShell 中文社区团队）'


class ADService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = DISPLAY_NAME
    _svc_description_ = DESCRIPTION

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ''))
        self._run()

    def _run(self):
        # 安装版数据目录固定到 ProgramData（先于 import config 设置，确保数据库/密钥落位正确）
        progdata = os.environ.get('PROGRAMDATA') or r'C:\ProgramData'
        os.environ['ADM_WORK_DIR'] = os.path.join(progdata, 'AD域控管理系统')

        import config
        from waitress.server import create_server
        from app import app

        os.chdir(config.WORK_DIR)
        # 用可关闭的 server 对象（而非阻塞的 serve()），配合停止事件实现优雅停机
        self.server = create_server(app, host=config.SERVER_HOST, port=config.SERVER_PORT, threads=8)
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)

        t = threading.Thread(target=self.server.run, daemon=True)
        t.start()

        # 主线程阻塞等待 SCM 的停止信号
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        # 收到停止信号：关闭监听 socket，等待后台线程退出
        try:
            self.server.close()
        except Exception:
            pass
        t.join(timeout=8)
        if t.is_alive():
            # 兜底：仍在处理连接时直接结束进程（SQLite WAL 模式下强杀安全）
            os._exit(0)


def _scm():
    return win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)


def _service_log(msg: str) -> None:
    """服务安装/删除的日志（写 exe 同级 logs/service.log，便于交付后排查）。"""
    try:
        base = os.path.dirname(os.path.abspath(sys.executable))
        d = os.path.join(base, 'logs')
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, 'service.log'), 'a', encoding='utf-8') as f:
            f.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg))
    except Exception:
        pass


def install_service():
    exe = os.path.abspath(sys.executable)
    binpath = f'"{exe}" --run-service'
    try:
        scm = _scm()
    except Exception as e:
        _service_log('打开服务控制管理器失败（需管理员权限）: %s' % e)
        raise
    try:
        try:
            hs = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
            win32service.ChangeServiceConfig(
                hs, win32service.SERVICE_NO_CHANGE, win32service.SERVICE_AUTO_START,
                win32service.SERVICE_ERROR_NORMAL, binpath, None, 0, None, None, None,
                DISPLAY_NAME)
            _service_log('服务已存在，配置已更新为开机自启')
        except pywintypes.error as e:
            # 1060 = 指定的服务未安装（首次安装的正常路径）
            if getattr(e, 'winerror', None) != 1060:
                raise
            # 注意：pywin32 的 CreateService 参数顺序是 loadOrderGroup, tagId, dependencies,
            # userName, password —— tagId 必须在 dependencies 之前且为整数 0（None 会 TypeError）
            hs = win32service.CreateService(
                scm, SERVICE_NAME, DISPLAY_NAME, win32service.SERVICE_ALL_ACCESS,
                win32service.SERVICE_WIN32_OWN_PROCESS, win32service.SERVICE_AUTO_START,
                win32service.SERVICE_ERROR_NORMAL, binpath,
                None,      # loadOrderGroup
                0,         # tagId
                None,      # dependencies
                None,      # userName（None = LocalSystem）
                None)      # password
            _service_log('服务已安装并设为开机自启')
        try:
            win32service.ChangeServiceConfig2(hs, win32service.SERVICE_CONFIG_DESCRIPTION, DESCRIPTION)
        except Exception:
            pass
        win32service.CloseServiceHandle(hs)
    finally:
        win32service.CloseServiceHandle(scm)


def remove_service():
    try:
        scm = _scm()
    except Exception as e:
        _service_log('打开服务控制管理器失败（需管理员权限）: %s' % e)
        raise
    try:
        try:
            hs = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_ALL_ACCESS)
            win32service.DeleteService(hs)
            win32service.CloseServiceHandle(hs)
            _service_log('服务已删除')
        except pywintypes.error as e:
            if getattr(e, 'winerror', None) == 1060:
                _service_log('服务不存在，无需删除')
            else:
                raise
    finally:
        win32service.CloseServiceHandle(scm)


def run_service():
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(ADService)
    servicemanager.StartServiceCtrlDispatcher()
