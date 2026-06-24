{ Shared NetGuard cleanup routines for setup and standalone uninstaller. }

procedure KillNetGuardProcesses;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /IM NetGuard-API.exe', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM arp-scanner.exe', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM arp-spoof-detector.exe', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
end;

function RunRegisteredUninstaller: Boolean;
var
  UninstallKey: String;
  UninstallString: String;
  ResultCode: Integer;
begin
  Result := False;
  UninstallKey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
    '{A7B3C9D1-4E2F-4A8B-9C1D-2F3E4A5B6C7D}_is1';

  if RegQueryStringValue(HKLM, UninstallKey, 'UninstallString', UninstallString) or
     RegQueryStringValue(HKCU, UninstallKey, 'UninstallString', UninstallString) then
  begin
    if Exec(RemoveQuotes(UninstallString), '/SILENT /NORESTART', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode) then
      Result := True;
  end;
end;

procedure DeleteDirIfExists(const Dir: String);
begin
  if DirExists(Dir) then
    DelTree(Dir, True, True, True);
end;

procedure DeleteFileIfExists(const FileName: String);
begin
  if FileExists(FileName) then
    DeleteFile(FileName);
end;

procedure RemoveStartMenuShortcuts;
begin
  DeleteDirIfExists(ExpandConstant('{commonprograms}\NetGuard'));
  DeleteDirIfExists(ExpandConstant('{userprograms}\NetGuard'));
end;

procedure RemoveDesktopShortcut;
begin
  DeleteFileIfExists(ExpandConstant('{commondesktop}\NetGuard.lnk'));
  DeleteFileIfExists(ExpandConstant('{userdesktop}\NetGuard.lnk'));
end;

procedure DeleteNetGuardUserData;
var
  UsersDir: String;
  FindRec: TFindRec;
  DataDir: String;
begin
  DeleteDirIfExists(ExpandConstant('{localappdata}\NetGuard'));

  UsersDir := ExpandConstant('{sd}\Users');
  if FindFirst(UsersDir + '\*', FindRec) then
  try
    repeat
      if (FindRec.Name <> '.') and (FindRec.Name <> '..') and
         (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY <> 0) then
      begin
        DataDir := UsersDir + '\' + FindRec.Name + '\AppData\Local\NetGuard';
        DeleteDirIfExists(DataDir);
      end;
    until not FindNext(FindRec);
  finally
    FindClose(FindRec);
  end;
end;

procedure PerformNetGuardCleanup(DeleteUserData: Boolean);
var
  InstallDir: String;
begin
  KillNetGuardProcesses;
  RunRegisteredUninstaller;

  InstallDir := ExpandConstant('{autopf}\NetGuard');
  DeleteFileIfExists(InstallDir + '\netguard.db');
  DeleteDirIfExists(InstallDir);

  if DeleteUserData then
    DeleteNetGuardUserData;

  RemoveStartMenuShortcuts;
  RemoveDesktopShortcut;
end;
