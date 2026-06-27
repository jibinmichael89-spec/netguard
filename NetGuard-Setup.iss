#define MyAppName "NetGuard"
#define MyAppVersion "1.2.0"
#define MyAppPublisher "NetGuard"
#define MyAppExeName "NetGuard-API.exe"
#define LauncherScript "START-NetGuard.bat"
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
Source: "dist\{#LauncherScript}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\START-ARP-Scanner.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\START-ARP-Spoof-Detector.bat"; DestDir: "{app}"; Flags: ignoreversion

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

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    KillNetGuardProcesses;
  if CurUninstallStep = usPostUninstall then
    DeleteNetGuardUserData;
end;
