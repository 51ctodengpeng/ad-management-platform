; ============================================================================
;  AD 域控管理系统 - Inno Setup 安装包脚本（Windows 服务版）
;  编译：项目根目录执行
;        "C:\Users\<你>\AppData\Local\Programs\Inno Setup 6\ISCC.exe" deploy\installer.iss
;  产物：deploy\output\AD域控管理系统_安装程序_v1.0.2.exe
;
;  自启方案：注册为 Windows 服务（pywin32，服务名 ADDomainManager）
;   - 开机自启（SERVICE_AUTO_START），无黑框后台运行
;   - 可在 services.msc 中启动/停止/管理
;   - 服务内部把数据目录固定到 %ProgramData%\AD域控管理系统（可写）
;   - 监听 0.0.0.0:8080（局域网可访问）
; ============================================================================

#define MyAppName "AD域控管理系统"
#define MyAppVersion "1.0.3"
#define MyAppPublisher "PowerShell 中文社区团队"
#define MyAppExeName "AD域控管理系统.exe"
#define MyServiceName "ADDomainManager"
#define MyDataDir "{commonappdata}\AD域控管理系统"
#define MyAppId "{{7C3E1B42-9F0A-4D6E-9B21-5A7C8D3E6F10}"
#define MyURL "http://localhost:8080/"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppSupportURL=https://www.powershell.com.cn
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=AD域控管理系统_安装程序_v{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupIconFile=adm.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
Uninstallable=yes
MinVersion=10.0
CloseApplications=yes
RestartApplications=no

; 说明：如需中文安装界面，请将官方 ChineseSimplified.isl 放入
; Inno Setup 6\Languages\ 目录，并取消下面 [Languages] 段注释。
; [Languages]
; Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut (open web console)"; GroupDescription: "Additional icons:"; Flags: checkedonce

[Files]
Source: "..\dist\AD域控管理系统.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README_部署说明.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Dirs]
Name: "{#MyDataDir}"; Permissions: users-modify
Name: "{#MyDataDir}\database"; Permissions: users-modify
Name: "{#MyDataDir}\logs"; Permissions: users-modify

[Icons]
Name: "{group}\打开管理界面"; Filename: "{#MyURL}"
Name: "{group}\服务管理 (services.msc)"; Filename: "{sys}\services.msc"
Name: "{group}\数据目录"; Filename: "{#MyDataDir}"
Name: "{group}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"
; 桌面同时放「打开界面」与「卸载」快捷方式，确保卸载入口始终可达
Name: "{autodesktop}\{#MyAppName}"; Filename: "{#MyURL}"; Tasks: desktopicon
Name: "{autodesktop}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"; Tasks: desktopicon

[Run]
; ---- 注册 Windows 服务（无条件，核心功能；幂等：已存在则更新配置）----
Filename: "{app}\{#MyAppExeName}"; Parameters: "--install-service"; Flags: runhidden; StatusMsg: "正在注册 Windows 服务..."
; ---- 启动服务 ----
Filename: "{sys}\net.exe"; Parameters: "start {#MyServiceName}"; Flags: runhidden; StatusMsg: "正在启动服务..."
; ---- 打开管理界面 ----
Filename: "{#MyURL}"; Description: "在浏览器中打开管理界面"; Flags: shellexec nowait postinstall skipifsilent unchecked

[UninstallRun]
; 卸载：停止服务 + 删除服务 + 兜底杀进程
Filename: "{sys}\net.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden; RunOnceId: "StopSvc"
Filename: "{app}\{#MyAppExeName}"; Parameters: "--remove-service"; Flags: runhidden; RunOnceId: "DelSvc"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM ""{#MyAppExeName}"""; Flags: runhidden; RunOnceId: "KillApp"

[Code]
// 安装前检测是否已安装：若存在则提示「覆盖升级 / 取消」
function InitializeSetup(): Boolean;
var
  UninstStr: String;
  MsgResult: Integer;
  ResultCode: Integer;
begin
  Result := True;
  if RegQueryStringValue(HKEY_LOCAL_MACHINE,
      'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppId}_is1',
      'UninstallString', UninstStr) then
  begin
    MsgResult := MsgBox('检测到「{#MyAppName}」已安装。' + #13#10 + #13#10 +
                        '是否覆盖升级安装？' + #13#10 +
                        '· 选「是」：覆盖升级（保留已有数据）' + #13#10 +
                        '· 选「否」：取消本次安装',
                        mbConfirmation, MB_YESNO);
    if MsgResult = IDNO then
    begin
      Result := False;
      Exit;
    end;
    // 覆盖升级：先停服务 + 结束进程，避免 exe 被锁定导致文件覆盖失败
    Exec(ExpandConstant('{sys}\net.exe'), 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM "{#MyAppExeName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000);
  end;
end;

// 安装完成时校验 Windows 服务是否注册成功，失败给出明确提示
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if Exec(ExpandConstant('{sys}\sc.exe'), 'query {#MyServiceName}', '', SW_HIDE,
            ewWaitUntilTerminated, ResultCode) then
    begin
      if ResultCode <> 0 then
        MsgBox('警告：Windows 服务未成功注册/启动。' + #13#10 +
               '请打开 services.msc 确认「{#MyAppName}」服务是否存在，' + #13#10 +
               '或查看安装目录下的 logs\service.log 排查原因。', mbError, MB_OK);
    end;
  end;
end;

// 卸载开始时先停服务/删服务/杀进程（在删除文件之前执行，避免文件锁定导致卸载失败）
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec(ExpandConstant('{sys}\net.exe'), 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{app}\{#MyAppExeName}'), '--remove-service', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM "{#MyAppExeName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(800);
  end;
end;
