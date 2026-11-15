#Requires -RunAsAdministrator
param([switch]$Inspect)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root 'artifacts\wfp-tests.log'
New-Item -ItemType Directory -Force -Path (Split-Path $output) | Out-Null
try {
    $testArgs = @('--wfp')
    if ($Inspect) { $testArgs += '--inspect' }
    $process = Start-Process -FilePath (Join-Path $root 'tests\SelectiveVpn.Tests\bin\Release\net10.0-windows\SelectiveVpn.Tests.exe') -ArgumentList $testArgs -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput $output -RedirectStandardError (Join-Path $root 'artifacts\wfp-tests.stderr')
    $code = $process.ExitCode
} catch {
    $_ | Out-String | Add-Content -LiteralPath $output
    $code = 1
} finally {
    Set-Content -LiteralPath (Join-Path $root 'artifacts\wfp-tests.exit') -Value $code
}
exit $code
