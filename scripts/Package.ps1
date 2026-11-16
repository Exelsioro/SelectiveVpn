param([string]$Provider, [switch]$SkipBuild, [switch]$PassThru, [switch]$PublicRelease)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ($PublicRelease -and $Provider) { throw 'A public release cannot include a provider bootstrap.' }
if (!$PublicRelease) {
    if (!$Provider) { $Provider = Join-Path $root 'private\provider-bootstrap.json' }
    $providerFile = (Resolve-Path -LiteralPath $Provider).Path
    $providerData = Get-Content -LiteralPath $providerFile -Raw | ConvertFrom-Json
    if (!$providerData.ConnectionKeyBase64 -or [Convert]::FromBase64String($providerData.ConnectionKeyBase64).Length -eq 0) { throw 'Invalid provider bootstrap.' }
}
if (!$SkipBuild) { & (Join-Path $PSScriptRoot 'Build.ps1') -WithoutOpenVpn:$PublicRelease }
$version = Get-Date -Format 'yyyyMMdd-HHmmss'
$output = Join-Path $root 'artifacts\packages'
$package = Join-Path $output "SelectiveVpn-win-x64-$version"
New-Item -ItemType Directory -Path $package -Force | Out-Null
foreach ($dir in @('scripts','artifacts\publish','licenses')) { New-Item -ItemType Directory -Path (Join-Path $package $dir) -Force | Out-Null }
$published = Join-Path $root 'artifacts\publish'
$destination = Join-Path $package 'artifacts\publish'
if ($PublicRelease) {
    $service = Join-Path $destination 'Service'
    $runtime = New-Item -ItemType Directory -Path (Join-Path $service 'runtime') -Force
    Copy-Item -LiteralPath (Join-Path $published 'App'),(Join-Path $published 'THIRD-PARTY-NOTICES.txt') -Destination $destination -Recurse
    Get-ChildItem -LiteralPath (Join-Path $published 'Service') | Where-Object Name -ne 'runtime' |
        Copy-Item -Destination $service -Recurse
    Copy-Item -LiteralPath (Join-Path $published 'Service\runtime\sing-box.exe') -Destination $runtime.FullName
} else {
    Copy-Item -Path (Join-Path $published '*') -Destination $destination -Recurse
}
foreach ($script in @('Install.ps1','Uninstall.ps1','Setup.ps1','Test-Installed.ps1','ServiceRpc.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination (Join-Path $package 'scripts')
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'openvpn-manifest.json') -Destination (Join-Path $package 'scripts')
if (!$PublicRelease) {
    $privateDirectory = New-Item -ItemType Directory -Path (Join-Path $package 'private')
    Copy-Item -LiteralPath $providerFile -Destination $privateDirectory.FullName
}
Copy-Item -LiteralPath (Join-Path $root 'docs\INSTALL-RU.md') -Destination (Join-Path $package 'INSTALL-RU.txt')
Copy-Item -LiteralPath (Join-Path $root 'THIRD-PARTY-NOTICES.txt') -Destination $package
Copy-Item -LiteralPath (Join-Path $root 'runtime\sing-box-1.14.4-windows-amd64\LICENSE') -Destination (Join-Path $package 'licenses\sing-box-LICENSE.txt')
@'
@echo off
setlocal
echo Starting SelectiveVpn setup...
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Setup.ps1"
if errorlevel 1 (
    echo Setup did not complete. See install.log next to INSTALL.cmd if it was created.
    pause
)
'@ | Set-Content -LiteralPath (Join-Path $package 'INSTALL.cmd') -Encoding Ascii
# The manifest covers only the files staged for this package.
$manifest = foreach ($file in Get-ChildItem -LiteralPath $package -Recurse -File | Sort-Object FullName) {
    [pscustomobject]@{ Path = $file.FullName.Substring($package.Length + 1); SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $package 'SHA256SUMS.json') -Encoding UTF8
& (Join-Path $package 'scripts\Setup.ps1') -CheckOnly
$zip = "$package.zip"
Compress-Archive -Path $package -DestinationPath $zip -CompressionLevel Optimal
(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash + '  ' + (Split-Path -Leaf $zip) | Set-Content -LiteralPath "$zip.sha256" -Encoding Ascii
Write-Host "Package: $zip"
if ($PassThru) { Get-Item -LiteralPath $zip }
