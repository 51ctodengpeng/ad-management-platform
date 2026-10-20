@echo off
chcp 65001 >nul
rem ============================================================
rem  AD 域控管理系统 - 生产启动脚本（安装包内使用）
rem  工作目录固定到 %ProgramData%\AD域控管理系统，保证数据可写
rem ============================================================
setlocal

set "WORKDIR=%ProgramData%\AD域控管理系统"
if not exist "%WORKDIR%" mkdir "%WORKDIR%"
if not exist "%WORKDIR%\database" mkdir "%WORKDIR%\database"
if not exist "%WORKDIR%\logs" mkdir "%WORKDIR%\logs"

set "ADM_WORK_DIR=%WORKDIR%"
rem 生产环境建议改为固定随机值（长度 ≥32），避免重启后会话失效
if not defined ADM_SECRET_KEY set "ADM_SECRET_KEY=change-me-to-a-long-random-string-please"

cd /d "%~dp0"
echo ============================================================
echo  AD 域控管理系统 正在启动...
echo  数据目录：%WORKDIR%
echo  管理地址：http://127.0.0.1:8000/
echo  默认账号：admin / powershell@2025（登录后请立即修改）
echo  按 Ctrl+C 停止服务
echo ============================================================
"%~dp0AD域控管理系统.exe" --prod --host 0.0.0.0 --port 8000
