#define MyAppName "NetGuard Uninstaller"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "NetGuard"

[Setup]
AppId={{B8C4D0E2-5F3A-4B9C-0D2E-3F4A5B6C7D8E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={tmp}\NetGuard-Uninstall
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=no
DisableFinishedPage=no
DisableStartupPrompt=yes
CreateUninstallRegKey=no
Uninstallable=no
OutputDir=build\installer
OutputBaseFilename=NetGuard-Uninstall
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This will completely remove NetGuard from this computer, including:%n%n• Program Files\NetGuard%n• Start Menu shortcuts%n• Desktop shortcut (if present)%n• Database in %%LOCALAPPDATA%%\NetGuard%n• Leftover files from older installs%n%nRunning NetGuard processes will be stopped first.
FinishedLabel=NetGuard has been removed from this computer.

[Code]
#include "NetGuard-UninstallCode.iss"

function InitializeSetup(): Boolean;
begin
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    PerformNetGuardCleanup(True);
end;
