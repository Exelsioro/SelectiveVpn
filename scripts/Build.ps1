param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    & (Join-Path $PSScriptRoot 'Get-Engine.ps1')
    & (Join-Path $PSScriptRoot 'Get-OpenVpn.ps1')
    dotnet build SelectiveVpn.slnx -c Release --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    if (!$SkipTests) {
        & '.\tests\SelectiveVpn.Tests\bin\Release\net10.0-windows\SelectiveVpn.Tests.exe'
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
    }
    foreach ($project in @('Service', 'App')) {
        dotnet publish "src\SelectiveVpn.$project\SelectiveVpn.$project.csproj" -c Release -r win-x64 --self-contained true -o "artifacts\publish\$project" --nologo
        if ($LASTEXITCODE -ne 0) { throw "Publish $project failed." }
    }
    $runtime = Join-Path $root 'artifacts\publish\Service\runtime'
    New-Item -ItemType Directory -Force -Path $runtime | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'runtime\sing-box.exe') -Destination $runtime -Force
    Copy-Item -LiteralPath (Join-Path $root 'runtime\openvpn') -Destination $runtime -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $root 'THIRD-PARTY-NOTICES.txt') -Destination (Join-Path $root 'artifacts\publish') -Force
    Write-Host "Ready: $root\artifacts\publish"
} finally { Pop-Location }
