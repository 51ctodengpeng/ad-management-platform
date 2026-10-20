' ============================================================
'  AD 域控管理系统 - 隐藏控制台启动（用于开机自启）
'  通过 WScript 以隐藏窗口方式调用 run_server.bat
' ============================================================
Option Explicit
Dim shell, fso, base, script
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
base = fso.GetParentFolderName(WScript.ScriptFullName)
script = base & "\run_server.bat"
' 0 = 隐藏窗口，False = 不等待退出
shell.Run """" & script & """", 0, False
