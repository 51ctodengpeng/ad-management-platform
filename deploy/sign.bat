@echo off
chcp 65001 >nul
setlocal
rem ============================================================
rem  AD 域控管理系统 - 代码签名脚本
rem  用法：打包完成后，双击本脚本（或命令行运行）对产物签名。
rem  前提：1) 已购买代码签名证书（.pfx 文件 或 UKey）
rem         2) 已安装 Windows SDK（含 signtool.exe）
rem  使用前请修改下方 4 个变量。
rem ============================================================

rem ---- 请修改为你的实际值 ----
set "PFX_FILE=C:\证书\powershell_codesign.pfx"
set "PFX_PASSWORD=你的证书密码"
set "TS_URL=http://timestamp.digicert.com"
set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"

rem ---- 待签名文件（打包产物）----
set "EXE=..\dist\AD域控管理系统.exe"
set "INSTALLER=..\deploy\output\AD域控管理系统_安装程序_v1.0.0.exe"

echo [1/3] 检查 signtool...
if not exist "%SIGNTOOL%" (
  echo   未找到 signtool.exe，请先安装 Windows SDK。
  echo   下载：https://developer.microsoft.com/windows/downloads/windows-sdk/
  goto :err
)

echo [2/3] 签名主程序 exe...
"%SIGNTOOL%" sign /fd SHA256 /tr "%TS_URL%" /td SHA256 /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%EXE%"
if errorlevel 1 goto :err

echo [3/3] 签名安装包...
"%SIGNTOOL%" sign /fd SHA256 /tr "%TS_URL%" /td SHA256 /f "%PFX_FILE%" /p "%PFX_PASSWORD%" "%INSTALLER%"
if errorlevel 1 goto :err

echo.
echo 签名完成，验证签名：
"%SIGNTOOL%" verify /pa /v "%EXE%" 2>&1 | findstr /C:"Successfully verified"
echo.
echo 全部完成。
pause
exit /b 0

:err
echo.
echo [错误] 签名失败，请检查证书路径、密码与 signtool 路径。
pause
exit /b 1
