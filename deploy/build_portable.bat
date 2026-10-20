@echo off
chcp 65001 >nul
setlocal
rem ============================================================
rem  AD 域控管理系统 - Windows 打包脚本
rem  用法：双击运行，或在项目根目录执行  deploy\build_portable.bat
rem  产物：dist\AD域控管理系统\AD域控管理系统.exe（单目录便携版）
rem        dist\AD域控管理系统_单文件.exe（onefile 便携版，启动稍慢）
rem ============================================================
cd /d "%~dp0.."

echo [1/4] 检查 Python 环境...
python -c "import sys; print('Python', sys.version)" || goto :err
where pyinstaller >nul 2>nul
if errorlevel 1 (
    echo [2/4] 安装依赖与 PyInstaller...
    python -m pip install -r requirements.txt pyinstaller || goto :err
) else (
    echo [2/4] 依赖已就绪，跳过安装
)

echo [3/4] 打包单目录版（推荐）...
python -m PyInstaller deploy\adm.spec --noconfirm --clean --distpath dist --workpath build || goto :err

echo [4/4] 打包单文件版...
python -m PyInstaller deploy\adm.spec --noconfirm --clean --onefile ^
    --distpath dist\onefile --workpath build\onefile || goto :err
if exist "dist\onefile\AD域控管理系统.exe" move /y "dist\onefile\AD域控管理系统.exe" "dist\AD域控管理系统_单文件.exe" >nul

echo.
echo ============================================================
echo  打包完成：
echo    单目录版  dist\AD域控管理系统\AD域控管理系统.exe
echo    单文件版  dist\AD域控管理系统_单文件.exe
echo.
echo  首次运行会在 exe 同级创建 database\ 与 logs\ 目录。
echo  默认账号 admin / powershell@2025，登录后请立即修改。
echo  如被 Windows Defender 拦截，请将 exe 加入白名单（见 deploy\README.md）
echo ============================================================
pause
exit /b 0

:err
echo.
echo [错误] 打包失败，请检查上方输出。
pause
exit /b 1
