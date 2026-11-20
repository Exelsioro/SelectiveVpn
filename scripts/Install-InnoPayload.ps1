#Requires -Version 5.1
param([Parameter(Mandatory)][string]$Archive, [switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
if (![Environment]::Is64BitProcess) { throw 'Run this installer with 64-bit PowerShell.' }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$CheckOnly -and !$admin) { throw 'Run setup as an administrator.' }
$target = [IO.Path]::GetFullPath((Join-Path ${env:ProgramW6432} 'SelectiveVpn'))
$serviceExe = Join-Path $target 'Service\SelectiveVpn.Service.exe'
$components = @('App', 'Service')
$payload = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $Archive).Path) ('SelectiveVpn-payload-' + [Guid]::NewGuid().ToString('N'))
$backup = Join-Path $target ('rollback-' + [Guid]::NewGuid().ToString('N'))
$moved = [Collections.Generic.List[string]]::new()
$copyStarted = $false
$serviceTouched = $false
$transcribing = $false
$committed = $false

function Assert-PlainPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Unsafe installation path: $Path" }
}

function Invoke-Control([string]$Command) {
    $reply = [SelectiveAcceptanceRpc]::Call(('{"command":"' + $Command + '"}'), $serviceExe, 4000) | ConvertFrom-Json
    if (!$reply.success) { throw $reply.error }
    $reply.status
}

function Wait-Control([datetime]$Deadline = [DateTime]::UtcNow.AddSeconds(150), [switch]$WaitForStartup) {
    do {
        $result = $null
        try { $result = Invoke-Control 'status' }
        catch {
            if ($_.Exception.GetBaseException() -isnot [TimeoutException]) { throw }
            if ([DateTime]::UtcNow -ge $Deadline -or (Get-Service SelectiveVpn).Status -eq 'Stopped') {
                throw "The SelectiveVpn service did not answer the local status request. $($_.Exception.GetBaseException().Message)"
            }
        }
        if ($result -and (!$WaitForStartup -or $result.state -ne 'Starting')) { return $result }
        if ([DateTime]::UtcNow -ge $Deadline) { throw "The SelectiveVpn service did not finish startup. $($result.message)" }
        Start-Sleep -Milliseconds 750
    } while ($true)
}

function Stop-VpnService {
    $service = Get-Service SelectiveVpn -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        if ($service.Status -ne 'StopPending') { Stop-Service SelectiveVpn }
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(45))
    }
}

function Start-VpnService([bool]$Reconnect) {
    Start-Service SelectiveVpn
    $result = Wait-Control -WaitForStartup
    Write-Host "Local service responded. State: $($result.state). $($result.message)"
    if (!$Reconnect -or $result.state -eq 'Connected') { return }

    try {
        if ($result.state -ne 'Connecting' -and !$result.connection.nextRetryAt) {
            $result = Invoke-Control 'connect'
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        while ($result.state -eq 'Connecting' -and [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 2
            $result = Wait-Control $deadline
        }
        if ($result.state -ne 'Connected') {
            Write-Warning "VPN connection is not ready. Open SelectiveVpn to check the connection status. $($result.message)"
        }
    } catch {
        Write-Warning "VPN connection could not be verified. Open SelectiveVpn to check the connection status. $($_.Exception.Message)"
    }
}

try {
    if (!$CheckOnly) {
        foreach ($path in @($target, (Join-Path $target 'Installer'), (Join-Path $target 'Installer\install.log'))) { Assert-PlainPath $path }
        $maintenance = Join-Path $target 'Installer'
        New-Item -ItemType Directory -Path $maintenance -Force | Out-Null
        Start-Transcript -LiteralPath (Join-Path $maintenance 'install.log') -Force | Out-Null
        $transcribing = $true
        Write-Host "Installer preflight. Process64=$([Environment]::Is64BitProcess), target=$target"
    }
    Expand-Archive -LiteralPath $Archive -DestinationPath $payload
    $packages = @(Get-ChildItem -LiteralPath $payload -Directory)
    if ($packages.Count -ne 1) { throw 'Expected a single package directory in the archive.' }
    $package = $packages[0].FullName
    & (Join-Path $package 'scripts\Setup.ps1') -CheckOnly
    if ($CheckOnly) { return }
    . (Join-Path $package 'scripts\ServiceRpc.ps1')

    foreach ($path in @($target, (Join-Path $target 'Installer'), (Join-Path $target 'Installer\install.log'),
            (Join-Path $target 'App'), (Join-Path $target 'Service'))) {
        Assert-PlainPath $path
    }
    $existing = Get-CimInstance Win32_Service -Filter "Name='SelectiveVpn'"
    if ($existing -and $existing.PathName.Trim('"') -ne $serviceExe) {
        throw 'Existing SelectiveVpn service uses a different installation path.'
    }
    if (Get-Process -Name SelectiveVpn.App -ErrorAction SilentlyContinue) {
        Write-Warning 'Exit SelectiveVpn from the tray before updating.'
        exit 12
    }

    $wasRunning = $existing -and $existing.State -in @('Running','Start Pending')
    $reconnect = $false
    if ($wasRunning) {
        try {
            $before = Invoke-Control 'status'
            $reconnect = $before.state -in @('Connected','Connecting') -or
                ($before.state -eq 'Faulted' -and $null -ne $before.connection.nextRetryAt)
        } catch {
            if ($_.Exception.GetBaseException() -isnot [TimeoutException]) { throw }
            Write-Warning 'The old service did not answer. Continuing with the update. Saved autoconnect settings still apply.'
        }
    }
    $serviceTouched = $true
    Stop-VpnService

    New-Item -ItemType Directory -Path $backup | Out-Null
    foreach ($component in $components) {
        $old = Join-Path $target $component
        if (Test-Path -LiteralPath $old) {
            Move-Item -LiteralPath $old -Destination (Join-Path $backup $component)
            $moved.Add($component)
        }
    }
    $copyStarted = $true
    & (Join-Path $package 'scripts\Install.ps1') -PreserveProvider -LeaveServiceStopped
    $previousOpenVpn = Join-Path $backup 'Service\runtime\openvpn'
    $installedOpenVpn = Join-Path $target 'Service\runtime\openvpn'
    if ((Test-Path -LiteralPath $previousOpenVpn) -and !(Test-Path -LiteralPath $installedOpenVpn)) {
        Assert-PlainPath (Split-Path -Parent $previousOpenVpn)
        Assert-PlainPath $previousOpenVpn
        $manifestPath = Join-Path $package 'scripts\openvpn-manifest.json'
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        New-Item -Path $installedOpenVpn -ItemType Directory | Out-Null
        foreach ($entry in $manifest.PSObject.Properties) {
            $file = Join-Path $previousOpenVpn $entry.Name
            Assert-PlainPath $file
            if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $entry.Value) {
                throw "Previously installed OpenVPN component mismatch: $($entry.Name)"
            }
            Copy-Item -LiteralPath $file -Destination $installedOpenVpn
        }
        Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $installedOpenVpn 'manifest.json')
        Write-Host 'Preserved previously installed OpenVPN runtime.'
    }
    if (!$existing -or $wasRunning) { Start-VpnService $reconnect }
    $committed = $true
    Write-Host 'SelectiveVpn installation verified.'
} catch {
    $failure = $_
    Write-Host ("Installation failed: " + $failure.Exception.Message)
    Write-Host $failure.ScriptStackTrace
    if ($serviceTouched) {
        try {
            Stop-VpnService
            if (!$existing -and (Get-Service SelectiveVpn -ErrorAction SilentlyContinue)) {
                & (Join-Path $package 'scripts\Uninstall.ps1') -RemoveApplicationBlocks
            }
            if ($copyStarted) {
                foreach ($component in $components) {
                    $path = Join-Path $target $component
                    if (Test-Path -LiteralPath $path) {
                        Assert-PlainPath $path
                        Move-Item -LiteralPath $path -Destination (Join-Path $backup ('failed-' + $component))
                    }
                }
            }
            foreach ($component in $moved) {
                Move-Item -LiteralPath (Join-Path $backup $component) -Destination (Join-Path $target $component)
            }
            Write-Warning 'Previous application files restored.'
            if ($wasRunning) {
                try { Start-VpnService $reconnect }
                catch { Write-Warning ("Restored service did not become ready: " + $_.Exception.Message) }
            }
        } catch {
            Write-Warning ("Could not restore application files. Backup: $backup. " + $_.Exception.Message)
        }
    }
    throw $failure
} finally {
    if ($committed -and (Test-Path -LiteralPath $backup)) {
        try {
            $resolved = (Resolve-Path -LiteralPath $backup).Path
            $rootPrefix = $target.TrimEnd('\') + '\rollback-'
            if ($resolved.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase) -and
                !(Get-ChildItem -LiteralPath $resolved -Recurse -Force -Attributes ReparsePoint)) {
                Remove-Item -LiteralPath $resolved -Recurse -Force
            }
        } catch { Write-Warning "Previous version retained at $backup." }
    }
    if ($transcribing) { Stop-Transcript | Out-Null }
}
