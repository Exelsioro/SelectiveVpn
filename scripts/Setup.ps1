param([switch]$CheckOnly)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
function Test-Package {
    $entries = (Get-Content -LiteralPath (Join-Path $root 'SHA256SUMS.json') -Raw | ConvertFrom-Json)
    if ($entries.Count -lt 10) { throw 'Package manifest is incomplete.' }
    foreach ($entry in $entries) {
        $path = [IO.Path]::GetFullPath((Join-Path $root $entry.Path))
        if (!$path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid package path.' }
        if (!(Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.SHA256) { throw "Missing or damaged file: $($entry.Path)" }
    }
    foreach ($required in @('private\provider-bootstrap.json', 'scripts\Install.ps1', 'artifacts\publish\App\SelectiveVpn.App.exe', 'artifacts\publish\App\coreclr.dll', 'artifacts\publish\Service\SelectiveVpn.Service.exe', 'artifacts\publish\Service\coreclr.dll', 'artifacts\publish\Service\runtime\sing-box.exe', 'artifacts\publish\Service\runtime\openvpn\manifest.json')) {
        if ($required -notin $entries.Path) { throw "Missing manifest entry: $required" }
    }
    $runtime = Join-Path $root 'artifacts\publish\Service\runtime'
    $openvpn = Get-Content -LiteralPath (Join-Path $runtime 'openvpn\manifest.json') -Raw | ConvertFrom-Json
    foreach ($entry in $openvpn.PSObject.Properties) {
        if ((Get-FileHash -LiteralPath (Join-Path $runtime ('openvpn\' + $entry.Name)) -Algorithm SHA256).Hash -ne $entry.Value) { throw "OpenVPN component mismatch: $($entry.Name)" }
    }
    if ((Get-FileHash -LiteralPath (Join-Path $runtime 'sing-box.exe') -Algorithm SHA256).Hash -ne '8F30682EE198855440D2A7FE070D5D3653793B2D01BB8C85EEA88F93BBE7C8B9') { throw 'sing-box checksum mismatch.' }
    $provider = Get-Content -LiteralPath (Join-Path $root 'private\provider-bootstrap.json') -Raw | ConvertFrom-Json
    if (!$provider.ConnectionKeyBase64 -or [Convert]::FromBase64String($provider.ConnectionKeyBase64).Length -eq 0) { throw 'Invalid provider settings.' }
    Write-Host "Verified $($entries.Count) package files and VPN engines."
}
if ($CheckOnly) { Test-Package; return }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$admin) {
    $command = "& '" + $PSCommandPath.Replace("'", "''") + "'"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    Write-Host 'Approve the Windows administrator prompt. Installation opens in a separate console.'
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded) -Wait -PassThru
    exit $process.ExitCode
}
$log = Join-Path $root 'install.log'
Start-Transcript -LiteralPath $log -Append | Out-Null
try {
    if (![Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'This package requires Windows x64 (Intel/AMD).' }
    Write-Host 'Checking archive files and VPN engines...'
    Test-Package
    if (Get-Process -Name SelectiveVpn.App -ErrorAction SilentlyContinue) { throw 'Exit SelectiveVpn using its tray menu before updating.' }
    & (Join-Path $PSScriptRoot 'Install.ps1') -Provider (Join-Path $root 'private\provider-bootstrap.json')
    Write-Host 'Installation complete. Opening SelectiveVpn...'
    Start-Process (Join-Path $env:ProgramFiles 'SelectiveVpn\App\SelectiveVpn.App.exe')
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show('Installation complete. SelectiveVpn is available in the Start menu.', 'SelectiveVpn') | Out-Null
} catch {
    Write-Warning $_.Exception.Message
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show("Installation failed: $($_.Exception.Message)`r`nLog: $log", 'SelectiveVpn') | Out-Null
    exit 1
} finally { Stop-Transcript | Out-Null }
