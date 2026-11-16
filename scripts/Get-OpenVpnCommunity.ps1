$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'runtime\openvpn-community'
$manifestPath = Join-Path $PSScriptRoot 'openvpn-community-manifest.json'
$entries = (Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).PSObject.Properties

function Test-Hash([string]$Path, [string]$Expected) {
    (Test-Path -LiteralPath $Path -PathType Leaf) -and (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $Expected
}

$missing = @($entries | Where-Object { !(Test-Hash (Join-Path $target $_.Name) $_.Value) })
if ($missing.Count) {
    $work = (New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('SelectiveVpn-OpenVPN-' + [Guid]::NewGuid().ToString('N')))).FullName
    $msiName = 'OpenVPN-2.6.23-I002-amd64.msi'
    $msi = Join-Path $work $msiName
    Invoke-WebRequest -UseBasicParsing "https://swupdate.openvpn.org/community/releases/$msiName" -OutFile $msi
    if (!(Test-Hash $msi '31809E97DEBE44C12BE06ED892C2A43E55B67B31CB852827B7EC8F2D6C0B8DC6')) {
        throw 'OpenVPN MSI checksum mismatch.'
    }
    $extract = Join-Path $work 'extract'
    $arguments = '/a "' + $msi + '" /qn TARGETDIR="' + $extract + '" /norestart'
    $result = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
    if ($result.ExitCode -ne 0) { throw "OpenVPN administrative extraction failed: $($result.ExitCode)." }
    $wintun = Join-Path $work 'wintun.zip'
    Invoke-WebRequest -UseBasicParsing 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $wintun
    if (!(Test-Hash $wintun '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51')) {
        throw 'Wintun archive checksum mismatch.'
    }
    Expand-Archive -LiteralPath $wintun -DestinationPath $work
    $sources = @{
        'wintun.dll' = Join-Path $work 'wintun\bin\amd64\wintun.dll'
        'WINTUN-LICENSE.txt' = Join-Path $work 'wintun\LICENSE.txt'
        'OPENVPN-LICENSE.txt' = Join-Path $extract 'OpenVPN\license.txt'
    }
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    foreach ($entry in $entries) {
        $file = $sources[$entry.Name]
        if (!$file) { $file = Join-Path $extract ('OpenVPN\bin\' + $entry.Name) }
        if (!(Test-Hash $file $entry.Value)) { throw "OpenVPN Community component mismatch: $($entry.Name)" }
        Copy-Item -LiteralPath $file -Destination (Join-Path $target $entry.Name) -Force
    }
}
Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $target 'manifest.json') -Force
Write-Host 'Verified OpenVPN Community 2.6.23 and Wintun 0.14.1.'
