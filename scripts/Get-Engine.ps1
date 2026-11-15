$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$runtime = Join-Path $root 'runtime'
$version = '1.14.4'
$archiveHash = '99185D75D314A07DBBA4A130C8AD986CBEB629A07927975636B341CA61F991DF'
$exeHash = '8F30682EE198855440D2A7FE070D5D3653793B2D01BB8C85EEA88F93BBE7C8B9'
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$exe = Join-Path $runtime 'sing-box.exe'
if ((Test-Path -LiteralPath $exe) -and (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -eq $exeHash) { return }
$zip = Join-Path $runtime 'sing-box.zip'
Invoke-WebRequest "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip" -OutFile $zip
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $archiveHash) { throw 'Engine archive SHA256 mismatch.' }
Expand-Archive -LiteralPath $zip -DestinationPath $runtime -Force
Copy-Item -LiteralPath (Join-Path $runtime "sing-box-$version-windows-amd64\sing-box.exe") -Destination $exe -Force
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $exeHash) { throw 'Engine executable SHA256 mismatch.' }
Write-Host "Verified sing-box $version."
