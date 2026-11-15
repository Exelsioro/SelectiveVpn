#Requires -RunAsAdministrator
param([string]$Profiles)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'artifacts\publish'
$destination = Join-Path $env:ProgramFiles 'SelectiveVpn'
if (!(Test-Path -LiteralPath (Join-Path $source 'Service\SelectiveVpn.Service.exe'))) { throw 'Run scripts\Build.ps1 first.' }
$existing = Get-Service -Name SelectiveVpn -ErrorAction SilentlyContinue
if ($existing) { Stop-Service -Name SelectiveVpn -Force; $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) }
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $identity = New-Object Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
# Standard users need read/execute so Explorer can read the UI's UAC manifest.
$users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
Set-Acl -LiteralPath $destination -AclObject $acl
Copy-Item -Path (Join-Path $source '*') -Destination $destination -Recurse -Force
$serviceExe = Join-Path $destination 'Service\SelectiveVpn.Service.exe'
if ($Profiles) {
    $profilePath = (Resolve-Path -LiteralPath $Profiles).Path
    & $serviceExe --import-profiles $profilePath
    if ($LASTEXITCODE -ne 0) { throw 'Profile import failed.' }
}
if (!$existing) {
    New-Service -Name SelectiveVpn -BinaryPathName ('"' + $serviceExe + '"') -DisplayName 'SelectiveVpn routing service' -StartupType Automatic -DependsOn BFE -Description 'Selective routing with persistent application kill switch.' | Out-Null
}
& sc.exe failure SelectiveVpn reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot configure service recovery.' }
& sc.exe failureflag SelectiveVpn 1 | Out-Null
Start-Service -Name SelectiveVpn
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'SelectiveVpn.lnk'))
$shortcut.TargetPath = Join-Path $destination 'App\SelectiveVpn.App.exe'
$shortcut.WorkingDirectory = Split-Path $shortcut.TargetPath
$shortcut.Save()
Write-Host "Installed. Open SelectiveVpn from Start, or $destination\App\SelectiveVpn.App.exe"
