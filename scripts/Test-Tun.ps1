#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root 'artifacts\tun-tests.log'
try {
    $process = Start-Process -FilePath (Join-Path $root 'tests\SelectiveVpn.Tests\bin\Release\net10.0-windows\SelectiveVpn.Tests.exe') -ArgumentList '--tun' -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput $output -RedirectStandardError (Join-Path $root 'artifacts\tun-tests.stderr')
    $code = $process.ExitCode
} catch { $_ | Out-String | Add-Content -LiteralPath $output; $code = 1 }
finally {
    & ipconfig.exe /flushdns | Out-Null
    Set-Content -LiteralPath (Join-Path $root 'artifacts\tun-tests.exit') -Value $code
}
exit $code
