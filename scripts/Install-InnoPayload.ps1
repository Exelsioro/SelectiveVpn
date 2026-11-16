#Requires -Version 5.1
param([Parameter(Mandatory)][string]$Archive, [switch]$CheckOnly)

$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$CheckOnly -and !$admin) { throw 'Run setup as an administrator.' }
$target = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'SelectiveVpn'))
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

function Wait-Control([datetime]$Deadline = [DateTime]::UtcNow.AddSeconds(100)) {
    do {
        try { return (Invoke-Control 'status') }
        catch {
            if ([DateTime]::UtcNow -ge $deadline -or (Get-Service SelectiveVpn).Status -eq 'Stopped') { throw }
            Start-Sleep -Milliseconds 750
        }
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
    $result = Wait-Control
    if (!$Reconnect) { return }
    if ($result.state -notin @('Connected','Connecting')) { $result = Invoke-Control 'connect' }
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    while ($result.state -ne 'Connected') {
        if ($result.state -eq 'Faulted') { throw "VPN reconnection failed: $($result.message)" }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'VPN reconnection timed out.' }
        Start-Sleep -Seconds 2
        $result = Wait-Control $deadline
    }
}

try {
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
    $maintenance = Join-Path $target 'Installer'
    New-Item -ItemType Directory -Path $maintenance -Force | Out-Null
    Start-Transcript -LiteralPath (Join-Path $maintenance 'install.log') -Force | Out-Null
    $transcribing = $true
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
        $before = Wait-Control
        $reconnect = $before.state -in @('Connected','Connecting') -or
            ($before.state -eq 'Faulted' -and $null -ne $before.connection.nextRetryAt)
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
            if ($wasRunning) { Start-VpnService $reconnect }
            Write-Warning 'Previous installation restored.'
        } catch {
            Write-Warning ("Rollback incomplete. Backup: $backup. " + $_.Exception.Message)
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
