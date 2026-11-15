param([string]$Provider, [switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (!$Provider) { $Provider = Join-Path $root 'private\provider-bootstrap.json' }
$providerFile = (Resolve-Path -LiteralPath $Provider).Path
$providerData = Get-Content -LiteralPath $providerFile -Raw | ConvertFrom-Json
if (!$providerData.ConnectionKeyBase64 -or [Convert]::FromBase64String($providerData.ConnectionKeyBase64).Length -eq 0) { throw 'Invalid provider bootstrap.' }
if (!$SkipBuild) { & (Join-Path $PSScriptRoot 'Build.ps1') }
$version = Get-Date -Format 'yyyyMMdd-HHmmss'
$output = Join-Path $root 'artifacts\packages'
$package = Join-Path $output "SelectiveVpn-win-x64-$version"
New-Item -ItemType Directory -Path $package -Force | Out-Null
foreach ($dir in @('scripts','private','artifacts\publish','licenses')) { New-Item -ItemType Directory -Path (Join-Path $package $dir) -Force | Out-Null }
Copy-Item -Path (Join-Path $root 'artifacts\publish\*') -Destination (Join-Path $package 'artifacts\publish') -Recurse
foreach ($script in @('Install.ps1','Uninstall.ps1','Setup.ps1','Test-Installed.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination (Join-Path $package 'scripts')
}
Copy-Item -LiteralPath $providerFile -Destination (Join-Path $package 'private\provider-bootstrap.json')
Copy-Item -LiteralPath (Join-Path $root 'docs\INSTALL-RU.md') -Destination (Join-Path $package 'INSTALL-RU.txt')
Copy-Item -LiteralPath (Join-Path $root 'THIRD-PARTY-NOTICES.txt') -Destination $package
Copy-Item -LiteralPath (Join-Path $root 'runtime\sing-box-1.14.4-windows-amd64\LICENSE') -Destination (Join-Path $package 'licenses\sing-box-LICENSE.txt')
@'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Setup.ps1"
if errorlevel 1 pause
'@ | Set-Content -LiteralPath (Join-Path $package 'INSTALL.cmd') -Encoding Ascii
# Only explicitly selected provider bootstrap is packaged: no logs, DPAPI, personal rules or dumps.
$manifest = foreach ($file in Get-ChildItem -LiteralPath $package -Recurse -File | Sort-Object FullName) {
    [pscustomobject]@{ Path = $file.FullName.Substring($package.Length + 1); SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $package 'SHA256SUMS.json') -Encoding UTF8
& (Join-Path $package 'scripts\Setup.ps1') -CheckOnly
$zip = "$package.zip"
Compress-Archive -Path $package -DestinationPath $zip -CompressionLevel Optimal
(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash + '  ' + (Split-Path -Leaf $zip) | Set-Content -LiteralPath "$zip.sha256" -Encoding Ascii
Write-Host "Package: $zip"
