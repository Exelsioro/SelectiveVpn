#ifndef PayloadDirectory
  #error Define PayloadDirectory with the path containing SelectiveVpn-payload.zip
#endif
#ifndef Revision
  #define Revision "local"
#endif
#ifndef ProductVersion
  #define ProductVersion "0.1.0"
#endif

[Setup]
AppId={{BF83B659-F542-41F4-913D-73BB54CF6A4E}
AppName=SelectiveVpn
AppVersion={#ProductVersion}+{#Revision}
VersionInfoVersion={#ProductVersion}
DefaultDirName={autopf}\SelectiveVpn
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousAppDir=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0
CloseApplications=no
RestartApplications=no
AllowCancelDuringInstall=no
SetupLogging=yes
SetupMutex=SelectiveVpn-Setup
WizardStyle=modern
Compression=lzma2
OutputBaseFilename=SelectiveVpn-Setup-win-x64-{#Revision}
UninstallDisplayIcon={app}\App\SelectiveVpn.App.exe

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
russian.InstallingPayload=Установка SelectiveVpn и проверка службы. При обновлении VPN может ненадолго отключиться.
english.InstallingPayload=Installing SelectiveVpn and checking the service. An update may temporarily disconnect the VPN.
russian.InstallFailed=Установка не завершилась. Журнал установки: %1
english.InstallFailed=Installation did not complete. Installation log: %1
russian.CloseUi=Закройте SelectiveVpn через пункт «Выход» в меню трея, затем повторите установку.
english.CloseUi=Exit SelectiveVpn from the tray, then retry Setup.
russian.UninstallFailed=Не удалось остановить службу или снять её правила. Закройте SelectiveVpn через трей и попробуйте ещё раз.
english.UninstallFailed=Could not stop the service or remove its rules. Exit SelectiveVpn from the tray and try again.
russian.FixedPath=SelectiveVpn устанавливается в стандартную папку Program Files.
english.FixedPath=SelectiveVpn installs to its standard Program Files folder.
russian.LaunchApp=Открыть SelectiveVpn
english.LaunchApp=Open SelectiveVpn

[Files]
Source: "{#PayloadDirectory}\SelectiveVpn-payload.zip"; Flags: dontcopy nocompression
Source: "..\scripts\Install-InnoPayload.ps1"; Flags: dontcopy
Source: "..\scripts\Uninstall.ps1"; DestDir: "{app}\Installer"; Flags: ignoreversion

[Run]
Filename: "{app}\App\SelectiveVpn.App.exe"; Description: "{cm:LaunchApp}"; Flags: postinstall nowait skipifsilent runascurrentuser

[UninstallDelete]
Type: filesandordirs; Name: "{app}\App"
Type: filesandordirs; Name: "{app}\Service"
Type: files; Name: "{app}\Installer\install.log"
Type: dirifempty; Name: "{app}\Installer"

[Code]
function PowerShellPath: String;
begin
  Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  ScriptPath, Archive: String;
begin
  Result := '';
  if CompareText(RemoveBackslashUnlessRoot(WizardDirValue), ExpandConstant('{autopf}\SelectiveVpn')) <> 0 then
  begin
    Result := CustomMessage('FixedPath');
    Exit;
  end;
  WizardForm.PreparingLabel.Caption := CustomMessage('InstallingPayload');
  WizardForm.PreparingLabel.Repaint;
  ExtractTemporaryFile('Install-InnoPayload.ps1');
  ExtractTemporaryFile('SelectiveVpn-payload.zip');
  ScriptPath := ExpandConstant('{tmp}\Install-InnoPayload.ps1');
  Archive := ExpandConstant('{tmp}\SelectiveVpn-payload.zip');
  if not Exec(PowerShellPath, '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
      AddQuotes(ScriptPath) + ' -Archive ' + AddQuotes(Archive), ExpandConstant('{tmp}'),
      SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := FmtMessage(CustomMessage('InstallFailed'), [ExpandConstant('{app}\Installer\install.log')])
  else if ResultCode = 12 then
    Result := CustomMessage('CloseUi')
  else if ResultCode <> 0 then
    Result := FmtMessage(CustomMessage('InstallFailed'), [ExpandConstant('{app}\Installer\install.log')]);
end;

function InitializeUninstall: Boolean;
var
  Code: Integer;
begin
  Result := Exec(PowerShellPath, '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
    AddQuotes(ExpandConstant('{app}\Installer\Uninstall.ps1')) + ' -RemoveApplicationBlocks -RequireClosedUi',
    ExpandConstant('{app}\Installer'), SW_HIDE, ewWaitUntilTerminated, Code);
  Result := Result and (Code = 0);
  if not Result then SuppressibleMsgBox(CustomMessage('UninstallFailed'), mbError, MB_OK, IDOK);
end;
