@echo off
chcp 65001 >nul
rem ============================================================
rem  AD Domain Web Admin - source-code dev launcher
rem  Double-click to run independently (not tied to any session).
rem ============================================================
cd /d "%~dp0"
echo ============================================================
echo  AD Domain Web Admin - starting (source dev)...
echo  URL: http://127.0.0.1:8000
echo  Login: admin / powershell@2025
echo  Press Ctrl+C to stop.
echo ============================================================
"C:\Users\dengpeng\.workbuddy\binaries\python\envs\default\Scripts\python.exe" app.py --host 127.0.0.1 --port 8000
