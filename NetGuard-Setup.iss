#define MyAppName "NetGuard"
#define MyAppVersion "1.2.0"
#define MyAppPublisher "NetGuard"
#define MyAppExeName "NetGuard-API.exe"
#define LauncherScript "START-NetGuard.bat"
#define ServiceHostScript "NetGuard-ServiceHost.bat"
#define BuildDir "build\exe"

[Setup]
AppId={{A7B3C9D1-4E2F-4A8B-9C1D-2F3E4A5B6C7D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=build\installer
OutputBaseFilename=NetGuard-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start all NetGuard engines automatically at Windows boot"; GroupDescription: "Services:"; Flags: checkedonce

[Files]
Source: "{#BuildDir}\NetGuard-API.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\arp-scanner.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\arp-spoof-detector.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\risk-scorer.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\dns-monitor.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\rogue-dhcp-detector.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\inbound-connection-detector.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\policy-engine.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\threat-intel.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\msp-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\{#LauncherScript}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\{#ServiceHostScript}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\START-ARP-Scanner.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\START-ARP-Spoof-Detector.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\windows\Register-NetGuard-AutoStart.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\windows\Unregister-NetGuard-AutoStart.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "scripts\restart-api.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "scripts\restart-detector.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "scripts\Start-NetGuard-Services.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "scripts\Start-NetGuard-Engine.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "scripts\Verify-NetGuard-Windows.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "scripts\Repair-NetGuard-Windows.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\windows\Install-Npcap.ps1"; DestDir: "{app}"; Flags: ignoreversion
#ifexist "build\prerequisites\npcap-oem.exe"
Source: "build\prerequisites\npcap-oem.exe"; DestDir: "{tmp}"; DestName: "npcap-oem.exe"; Flags: deleteafterinstall
#endif
#ifexist "build\prerequisites\npcap-installer.exe"
Source: "build\prerequisites\npcap-installer.exe"; DestDir: "{tmp}"; DestName: "npcap-installer.exe"; Flags: deleteafterinstall
#endif
Source: "install\profiles\windows-home\netguard.env"; DestDir: "{app}"; Flags: ignoreversion
Source: "install\profiles\windows-msp\netguard.env"; DestDir: "{app}"; DestName: "netguard-msp.env.example"; Flags: ignoreversion
Source: "dist\README.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#LauncherScript}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\ARP Scanner"; Filename: "{app}\START-ARP-Scanner.bat"; IconFilename: "{app}\arp-scanner.exe"
Name: "{group}\ARP Spoof Guard"; Filename: "{app}\START-ARP-Spoof-Detector.bat"; IconFilename: "{app}\arp-spoof-detector.exe"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#LauncherScript}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#LauncherScript}"; Description: "Open {#MyAppName} Dashboard"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\netguard.db"

[Code]
#include "NetGuard-UninstallCode.iss"

procedure InstallBundledNpcap();
var
  ResultCode: Integer;
begin
  if FileExists(ExpandConstant('{pf}\Npcap\NPFInstall.exe')) or
     FileExists(ExpandConstant('{pf}\Npcap\wpcap.dll')) then
    Exit;

  if (not FileExists(ExpandConstant('{tmp}\npcap-oem.exe'))) and
     (not FileExists(ExpandConstant('{tmp}\npcap-installer.exe'))) then
    Exit;

  Exec('powershell.exe',
    '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' +
    ExpandConstant('{app}\Install-Npcap.ps1') + '" -PrereqDir "' +
    ExpandConstant('{tmp}') + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if (ResultCode <> 0) and
     (not FileExists(ExpandConstant('{pf}\Npcap\NPFInstall.exe'))) and
     (not FileExists(ExpandConstant('{pf}\Npcap\wpcap.dll'))) then
    MsgBox(
      'NetGuard could not install the Npcap packet capture driver.' + #13#10 + #13#10 +
      'DNS, Rogue DHCP, and Inbound monitoring need Npcap.' + #13#10 +
      'Install from https://npcap.com then run Repair from the NetGuard folder.',
      mbError, MB_OK);
end;

procedure RegisterAutoStartTasks();
var
  ResultCode: Integer;
  AppDir: String;
begin
  AppDir := ExpandConstant('{app}');
  if FileExists(AppDir + '\netguard.db') then
    DeleteFile(AppDir + '\netguard.db');

  if not WizardIsTaskSelected('autostart') then
    Exit;
  Exec('powershell.exe',
    '-NoProfile -ExecutionPolicy Bypass -File "' +
    ExpandConstant('{app}\Register-NetGuard-AutoStart.ps1') +
    '" -InstallDir "' + ExpandConstant('{app}') + '" -Profile home',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    InstallBundledNpcap();
    RegisterAutoStartTasks();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    KillNetGuardProcesses;
    Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' +
      ExpandConstant('{app}\Unregister-NetGuard-AutoStart.ps1') + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if CurUninstallStep = usPostUninstall then
    DeleteNetGuardUserData;
end;
