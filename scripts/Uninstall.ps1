#Requires -RunAsAdministrator
param([switch]$RemoveApplicationBlocks, [switch]$RequireClosedUi)
$ErrorActionPreference = 'Stop'
$destination = Join-Path $env:ProgramFiles 'SelectiveVpn'
if ($RequireClosedUi) {
    if (Get-Process -Name SelectiveVpn.App -ErrorAction SilentlyContinue) { throw 'Exit SelectiveVpn from the tray before uninstalling.' }
    foreach ($path in @($destination, (Join-Path $destination 'App'), (Join-Path $destination 'Service'))) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Unsafe installation path: $path" }
    }
}
Get-ScheduledTask -TaskName 'SelectiveVpn.UI.*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
$service = Get-Service -Name SelectiveVpn -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service -Name SelectiveVpn -Force
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    & sc.exe delete SelectiveVpn | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot remove service.' }
}
if ($RemoveApplicationBlocks) {
    & (Join-Path $destination 'Service\SelectiveVpn.Service.exe') --remove-protection
    if ($LASTEXITCODE -ne 0) { throw 'Cannot remove application blocks.' }
    Write-Host 'Application blocks removed. These apps may now use the direct connection.'
} else {
    Write-Host 'Application blocks are retained. Run again with -RemoveApplicationBlocks to explicitly remove them.'
}
$shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'SelectiveVpn.lnk'
if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut }
Write-Host 'Service removed. Binaries and encrypted settings are retained for recovery.'
