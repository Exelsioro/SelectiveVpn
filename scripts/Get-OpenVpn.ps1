param([string]$Source = 'D:\PlanetVPN\bin\openvpn')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'runtime\openvpn'
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'openvpn-manifest.json') -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Force -Path $target | Out-Null
foreach ($entry in $manifest.PSObject.Properties) {
    $file = Join-Path $target $entry.Name
    if (!(Test-Path -LiteralPath $file) -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $entry.Value) {
        $original = Join-Path $Source $entry.Name
        if (!(Test-Path -LiteralPath $original) -or (Get-FileHash -LiteralPath $original -Algorithm SHA256).Hash -ne $entry.Value) { throw "Verified OpenVPN component unavailable: $($entry.Name). Supply -Source with the original PlanetVPN OpenVPN directory." }
        Copy-Item -LiteralPath $original -Destination $file -Force
    }
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'openvpn-manifest.json') -Destination (Join-Path $target 'manifest.json') -Force
