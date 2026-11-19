#Requires -RunAsAdministrator
param([string]$Profiles, [string]$Provider, [switch]$PreserveProvider, [switch]$LeaveServiceStopped)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'artifacts\publish'
$destination = Join-Path ${env:ProgramW6432} 'SelectiveVpn'
if (!(Test-Path -LiteralPath (Join-Path $source 'Service\SelectiveVpn.Service.exe'))) { throw 'Run scripts\Build.ps1 first.' }
$existing = Get-Service -Name SelectiveVpn -ErrorAction SilentlyContinue
$uiPath = Join-Path $destination 'App\SelectiveVpn.App.exe'
foreach ($ui in @(Get-Process -Name SelectiveVpn.App -ErrorAction SilentlyContinue)) {
    if ($ui.Path -eq $uiPath) {
        throw 'Exit SelectiveVpn from the tray menu before updating. Save any pending edits first.'
    }
}
Write-Host 'Copying SelectiveVpn and the VPN engines...'
if ($existing -and $existing.Status -ne 'Stopped') {
    Stop-Service -Name SelectiveVpn -Force
    $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
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
$providerStore = Join-Path $env:ProgramData 'SelectiveVpn\provider.dpapi'
if ($PreserveProvider -and (Test-Path -LiteralPath $providerStore -PathType Leaf)) { $Provider = $null }
elseif (!$Provider) { $candidate = Join-Path $root 'private\provider-bootstrap.json'; if (Test-Path -LiteralPath $candidate) { $Provider = $candidate } }
if ($Provider) {
    Write-Host 'Importing provider settings...'
    & $serviceExe --import-provider (Resolve-Path -LiteralPath $Provider).Path
    if ($LASTEXITCODE -ne 0) { throw 'Provider import failed.' }
    Write-Host 'Trying to download the PlanetVPN catalog (up to 45 seconds)...'
    try {
        $refresh = Start-Process -FilePath $serviceExe -ArgumentList '--refresh-catalog' -NoNewWindow -PassThru
        try {
            $clock = [Diagnostics.Stopwatch]::StartNew()
            while (!$refresh.WaitForExit(5000) -and $clock.Elapsed.TotalSeconds -lt 45) {
                Write-Host ("Waiting for the provider ({0:F0} seconds)..." -f $clock.Elapsed.TotalSeconds)
            }
            $refresh.Refresh()
            if (!$refresh.HasExited) {
                try { $refresh.Kill() } catch { if (!$refresh.HasExited) { throw } }
                if (!$refresh.WaitForExit(5000)) { throw 'Catalog downloader did not stop.' }
                Write-Warning 'Catalog download timed out. Refresh PlanetVPN in the Servers tab after installation.'
            } elseif ($refresh.ExitCode -ne 0) {
                Write-Warning 'Catalog update failed. Refresh PlanetVPN in the Servers tab.'
            }
        } finally { $refresh.Dispose() }
    } catch {
        Write-Warning ('Could not download the catalog. Refresh PlanetVPN in the Servers tab. ' + $_.Exception.Message)
    }
}
Write-Host 'Installing and starting the Windows service...'
if (!$existing) {
    New-Service -Name SelectiveVpn -BinaryPathName ('"' + $serviceExe + '"') -DisplayName 'SelectiveVpn routing service' -StartupType Automatic -DependsOn BFE -Description 'Selective routing with persistent application kill switch.' | Out-Null
}
& sc.exe failure SelectiveVpn reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Cannot configure service recovery.' }
& sc.exe failureflag SelectiveVpn 1 | Out-Null
if (!$LeaveServiceStopped) { Start-Service -Name SelectiveVpn }
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'SelectiveVpn.lnk'))
$shortcut.TargetPath = Join-Path $destination 'App\SelectiveVpn.App.exe'
$shortcut.WorkingDirectory = Split-Path $shortcut.TargetPath
$shortcut.Save()
Write-Host "Installed. Open SelectiveVpn from Start, or $destination\App\SelectiveVpn.App.exe"
