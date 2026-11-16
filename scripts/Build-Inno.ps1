param([string]$Iscc, [string]$Package, [switch]$SkipBuild, [switch]$PrivateBundle)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (!$Iscc) {
    $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($command) { $Iscc = $command.Source }
}
if (!$Iscc) {
    $locations = @("$env:LOCALAPPDATA\Programs\Inno Setup 7", "$env:LOCALAPPDATA\Programs\Inno Setup 6",
        "${env:ProgramFiles(x86)}\Inno Setup 7", "${env:ProgramFiles(x86)}\Inno Setup 6",
        "$env:ProgramFiles\Inno Setup 7", "$env:ProgramFiles\Inno Setup 6")
    $Iscc = $locations | ForEach-Object { Join-Path $_ 'ISCC.exe' } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}
if (!$Iscc) { throw 'Install Inno Setup 6/7 or provide the path to ISCC.exe with -Iscc.' }

if (!$Package) {
    $output = & (Join-Path $PSScriptRoot 'Package.ps1') -SkipBuild:$SkipBuild -PassThru -PublicRelease:(!$PrivateBundle)
    $output | Where-Object { $_ -isnot [IO.FileInfo] } | Write-Host
    $Package = ($output | Where-Object { $_ -is [IO.FileInfo] } | Select-Object -Last 1).FullName
}
if (!$Package) { throw 'No installation ZIP was produced.' }
$Package = (Resolve-Path -LiteralPath $Package).Path
$outputDirectory = Join-Path $root 'artifacts\inno'
$staging = Join-Path $outputDirectory ('stage-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null
$payload = Join-Path $staging 'SelectiveVpn-payload.zip'
$versionDll = Join-Path $staging 'SelectiveVpn.Service.dll'
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Package)
    try {
        $entries = @($zip.Entries | Where-Object { $_.FullName.Replace('\','/') -match '^[^/]+/artifacts/publish/Service/SelectiveVpn\.Service\.dll$' })
        if ($entries.Count -ne 1) { throw 'The ZIP does not contain a unique SelectiveVpn service.' }
        $prefix = ($entries[0].FullName.Replace('\','/') -split '/',2)[0] + '/'
        if (!($zip.Entries | Where-Object { $_.FullName.Replace('\','/') -eq ($prefix + 'scripts/ServiceRpc.ps1') })) {
            throw 'The ZIP predates Inno updates. Rebuild it with scripts\Package.ps1.'
        }
        if (!$PrivateBundle -and ($zip.Entries | Where-Object {
            $_.FullName.Replace('\','/') -match '(^|/)(private|openvpn)(/|$)|\.(dpapi|ovpn|log)$'
        })) {
            throw 'This ZIP contains files reserved for private installations.'
        }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $versionDll)
    } finally { $zip.Dispose() }
    $assemblyVersion = (Get-Item -LiteralPath $versionDll).VersionInfo.ProductVersion
    if ($assemblyVersion -notmatch '^(?<version>\d+\.\d+\.\d+)\+(?<sha>[a-f0-9]{7,40})') {
        throw 'The packaged service has no usable Git version.'
    }
    $version = $Matches['version']
    $revision = $Matches['sha'].Substring(0, 7)
    Copy-Item -LiteralPath $Package -Destination $payload
    $installerName = 'SelectiveVpn-Setup-win-x64'
    if ($PrivateBundle) { $installerName += "-$revision-private" }
    & $Iscc "/DPayloadDirectory=$staging" "/DRevision=$revision" "/DProductVersion=$version" "/O$outputDirectory" "/F$installerName" (Join-Path $root 'installer\SelectiveVpn.iss')
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE." }
    $installer = Join-Path $outputDirectory "$installerName.exe"
    $hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash
    "$hash  $([IO.Path]::GetFileName($installer))" | Set-Content -LiteralPath "$installer.sha256" -Encoding Ascii
    Write-Host "Inno Setup installer: $installer"
} finally {
    Remove-Item -LiteralPath $payload,$versionDll -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $staging -ErrorAction SilentlyContinue
}
