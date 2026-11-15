#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateRange(30,600)][int]$ConnectionTimeoutSeconds = 180,
    [switch]$CheckOnly,
    [switch]$Recover,
    [switch]$Watchdog,
    [string]$RunDirectory,
    [int]$OwnerPid,
    [long]$OwnerStartTicks
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$runs = Join-Path $root 'artifacts\acceptance'
$data = Join-Path $env:ProgramData 'SelectiveVpn'
$settingsFile = Join-Path $data 'settings.json'
$serviceExe = Join-Path $env:ProgramFiles 'SelectiveVpn\Service\SelectiveVpn.Service.exe'
$script:results = [Collections.Generic.List[object]]::new()
$script:backupReady = $false
$script:cleanupOk = $false
$script:run = $null
$script:exitCode = 1
$utf8 = [Text.UTF8Encoding]::new($false)

# Bounded framed RPC with the same installed-image check as the application UI.
if (-not ('SelectiveAcceptanceRpc' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
public static class SelectiveAcceptanceRpc {
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
 static void Wait(Task task, Stopwatch watch, int timeout) {
   int left = timeout - (int)watch.ElapsedMilliseconds;
   if (left <= 0 || !task.Wait(left)) throw new TimeoutException("VPN control request timed out");
   task.GetAwaiter().GetResult();
 }
 static byte[] Read(Stream stream, int size, Stopwatch watch, int timeout) {
   byte[] data = new byte[size]; int offset=0;
   while(offset<size) {
     Task<int> task=stream.ReadAsync(data,offset,size-offset);
     Wait(task,watch,timeout); int count=task.GetAwaiter().GetResult();
     if(count==0) throw new EndOfStreamException(); offset+=count;
   }
   return data;
 }
 public static string Call(string json, string expected, int timeout) {
   using(var pipe=new NamedPipeClientStream(".","SelectiveVpn.Control.v1",PipeDirection.InOut,PipeOptions.Asynchronous)) {
     pipe.Connect(2500); uint pid;
     if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid)) throw new IOException("Cannot identify RPC server");
     using(var process=Process.GetProcessById((int)pid))
       if(!String.Equals(process.MainModule.FileName,expected,StringComparison.OrdinalIgnoreCase))
         throw new UnauthorizedAccessException("Unexpected VPN service image");
     var watch=Stopwatch.StartNew(); byte[] bytes=Encoding.UTF8.GetBytes(json);
     Wait(pipe.WriteAsync(BitConverter.GetBytes(bytes.Length),0,4),watch,timeout);
     Wait(pipe.WriteAsync(bytes,0,bytes.Length),watch,timeout);
     int size=BitConverter.ToInt32(Read(pipe,4,watch,timeout),0);
     if(size<1 || size>5*1024*1024) throw new InvalidDataException("Invalid frame");
     return Encoding.UTF8.GetString(Read(pipe,size,watch,timeout));
   }
 }
}
'@
}

function Protect-Report($Path, [switch]$File) {
    if ($File) { $acl=[Security.AccessControl.FileSecurity]::new() }
    else { $acl=[Security.AccessControl.DirectorySecurity]::new() }
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity=[Security.Principal.SecurityIdentifier]::new($sid)
        if ($File) { $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','Allow') }
        else { $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow') }
        $acl.AddAccessRule($rule)
    }
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($File) { $rule=[Security.AccessControl.FileSystemAccessRule]::new($user,'Read','Allow') }
    else { $rule=[Security.AccessControl.FileSystemAccessRule]::new($user,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow') }
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Write-Json($Name, $Value) {
    [IO.File]::WriteAllText((Join-Path $script:run $Name), (ConvertTo-Json -InputObject $Value -Depth 32), $utf8)
}
function Event($Text) {
    $line = '{0:o} {1}' -f [DateTimeOffset]::Now,$Text
    Write-Host $Text
    if ($script:run) { [IO.File]::AppendAllText((Join-Path $script:run 'test.log'),$line+[Environment]::NewLine,$utf8) }
}
function Result($Name, $State, $Detail) {
    $entry = [ordered]@{name=$Name;result=$State;detail=$Detail;time=[DateTimeOffset]::Now.ToString('o')}
    $script:results.Add($entry)
    Event "$State : $Name : $Detail"
    Write-Json 'checks.json' $script:results.ToArray()
}
function Assert-Check($Name, [bool]$Condition, $Detail) {
    if ($Condition) { Result $Name 'PASS' $Detail } else { Result $Name 'FAIL' $Detail }
}
function Rpc($Request) {
    $reply = [SelectiveAcceptanceRpc]::Call(($Request | ConvertTo-Json -Depth 32 -Compress),$serviceExe,90000) | ConvertFrom-Json
    if (!$reply.success) { throw $reply.error }
    return $reply.status
}
function Start-TestService {
    $svc=Get-Service SelectiveVpn
    if ($svc.Status -ne 'Running') { if ($svc.Status -ne 'StartPending') { $svc.Start() }; $svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(30)) }
    $until=[DateTime]::UtcNow.AddSeconds(30)
    do {
        try { return Rpc @{command='status'} } catch { if ([DateTime]::UtcNow -ge $until) { throw }; Start-Sleep -Milliseconds 500 }
    } while ($true)
}
function Stop-TestService {
    $svc=Get-Service SelectiveVpn
    if ($svc.Status -ne 'Stopped') { if ($svc.Status -ne 'StopPending') { $svc.Stop() }; $svc.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(60)) }
    $svc.Refresh()
    if ($svc.Status -ne 'Stopped') { throw 'Service did not stop' }
}
function Write-Settings($Text) {
    # Only called while the service is stopped; keep existing file ACL via Replace.
    $temp = Join-Path $data 'acceptance-settings.tmp'
    [IO.File]::WriteAllText($temp,$Text,$utf8)
    if (Test-Path -LiteralPath $settingsFile) { [IO.File]::Replace($temp,$settingsFile,[NullString]::Value) }
    else { [IO.File]::Move($temp,$settingsFile) }
}
function Snapshot($Name) {
    try {
        Write-Json "$Name-network.json" ([ordered]@{
            adapters=@(Get-NetAdapter | Select-Object Name,InterfaceIndex,Status,InterfaceDescription)
            routes=@(Get-NetRoute | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric,AddressFamily)
            dns=@(Get-DnsClientServerAddress | Select-Object InterfaceAlias,AddressFamily,ServerAddresses)
            service=(Get-Service SelectiveVpn | Select-Object Name,Status,StartType)
        })
    } catch { Event "Snapshot failed: $($_.Exception.Message)" }
}
function Collect-Logs {
    foreach ($name in @('service.log','engine.log','openvpn.log','service.log.previous','engine.log.previous','openvpn.log.previous')) {
        $source=Join-Path $data $name
        if (Test-Path -LiteralPath $source) {
            try { Copy-Item -LiteralPath $source -Destination (Join-Path $script:run $name) -Force } catch { Event "Cannot copy $name : $_" }
        }
    }
    try {
        $events=Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$script:started.LocalDateTime} -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'SelectiveVpn' } | Select-Object -First 50 TimeCreated,Id,ProviderName,LevelDisplayName,Message
        Write-Json 'application-events.json' @($events)
    } catch { Event "Application events unavailable: $_" }
}
function Validate-RunPath($Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if (!$full.StartsWith([IO.Path]::GetFullPath($runs).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Recovery directory must be inside artifacts\acceptance' }
    if (!(Test-Path -LiteralPath (Join-Path $full 'original-settings.json'))) { throw 'Original settings backup missing' }
    return $full
}
function Restore-AndStop {
    # Reapply original WFP application policy at startup, with autoconnect disabled.
    # Restore the original autoconnect value only AFTER the final service stop.
    $original=[IO.File]::ReadAllText((Join-Path $script:run 'original-settings.json'))
    $offline=$original | ConvertFrom-Json
    $offline.autoConnect=$false
    Stop-TestService
    Write-Settings ($offline | ConvertTo-Json -Depth 32 -Compress)
    try {
        $restored=Start-TestService
        Write-Json 'restored-status.json' $restored
        if ($restored.state -ne 'Disconnected') { throw 'Restoration did not start disconnected' }
        $expectedBlocks=@($offline.rules | Where-Object { $_.enabled -and $_.kind -eq 'Application' -and $_.target -eq 'Vpn' } | Select-Object -ExpandProperty value -Unique).Count
        if (!$restored.protectionActive -or $restored.protectedApplications -ne $expectedBlocks) { throw 'Original application protection not confirmed' }
    } finally {
        Stop-TestService
        Write-Settings $original
    }
    if ([IO.File]::ReadAllText($settingsFile) -ne $original) { throw 'Settings restoration verification failed' }
    $script:cleanupOk=$true
    [IO.File]::WriteAllText((Join-Path $script:run 'cleanup-complete.txt'),[DateTimeOffset]::Now.ToString('o'),$utf8)
}
function Probe($Exe, $Label, $Url, $Family='-4') {
    $stdout=Join-Path $script:run "$Label.stdout.txt"
    $stderr=Join-Path $script:run "$Label.stderr.txt"
    $probeArgs=@('--disable','--noproxy','*',$Family,'--silent','--show-error','--fail','--connect-timeout','5','--max-time','12',$Url)
    $proc=Start-Process -FilePath $Exe -ArgumentList $probeArgs -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    try {
        $null=$proc.Handle
        if (!$proc.WaitForExit(16000)) { $proc.Kill(); $proc.WaitForExit(); throw "Probe $Label exceeded deadline" }
        $proc.Refresh(); $code=$proc.ExitCode
        $body=[IO.File]::ReadAllText($stdout)
        $ip=''; $loc=''
        if ($body -match '(?m)^ip=([^\r\n]+)') { $ip=$Matches[1] }
        if ($body -match '(?m)^loc=([^\r\n]+)') { $loc=$Matches[1] }
        $result=[pscustomobject]@{label=$Label;exitCode=$code;ip=$ip;location=$loc;success=($code -eq 0 -and $ip.Length -gt 0);url=$Url;family=$Family}
        Write-Json "$Label.json" $result
        return $result
    } finally { $proc.Dispose() }
}
function Check-Blocked($Label) {
    $control=Probe $script:directProbe "$Label-control" 'https://1.1.1.1/cdn-cgi/trace'
    $protected=Probe $script:vpnProbe "$Label-protected" 'https://1.1.1.1/cdn-cgi/trace'
    if (!$control.success) { Result $Label 'INCONCLUSIVE' 'Direct control endpoint unavailable; timeout alone does not prove blocking' }
    else { Assert-Check $Label (!$protected.success -and $protected.exitCode -in @(7,28)) "Protected exit=$($protected.exitCode); direct control succeeded" }
    if ($script:ipv6Available) {
        $control6=Probe $script:directProbe "$Label-control-v6" 'https://[2606:4700:4700::1111]/cdn-cgi/trace' '-6'
        $protected6=Probe $script:vpnProbe "$Label-protected-v6" 'https://[2606:4700:4700::1111]/cdn-cgi/trace' '-6'
        if (!$control6.success) { Result "$Label IPv6" 'INCONCLUSIVE' 'IPv6 control unavailable' }
        else { Assert-Check "$Label IPv6" (!$protected6.success -and $protected6.exitCode -in @(7,28)) "Protected exit=$($protected6.exitCode); IPv6 control succeeded" }
    }
}
function Rule($Kind,$Value,$Target='Vpn') { return [pscustomobject]@{id=[guid]::NewGuid().ToString();enabled=$true;kind=$Kind;value=$Value;target=$Target} }
function Wait-Connected($Label) {
    $until=[DateTime]::UtcNow.AddSeconds($ConnectionTimeoutSeconds)
    $previous=''
    do {
        $s=Rpc @{command='status'}
        if ($s.message -ne $previous) { Event $s.message; $previous=$s.message }
        Write-Json "$Label-status.json" $s
        if ($s.state -eq 'Connected') { Result $Label 'PASS' $s.message; return }
        if ($s.state -eq 'Faulted') { throw "Connection failed: $($s.message)" }
        if ([DateTime]::UtcNow -ge $until) { throw "Connection deadline exceeded ($ConnectionTimeoutSeconds s)" }
        Start-Sleep -Seconds 2
    } while ($true)
}
function Save-TestRules($Rules,$Label,[bool]$Online=$true) {
    $script:testSettings.rules=@($script:preservedBlocks)+@($Rules)
    $null=Rpc @{command='save';settings=$script:testSettings}
    if ($Online) { Wait-Connected $Label }
}

if ($Watchdog -or $Recover) {
    $script:run=Validate-RunPath $RunDirectory
    if ($Watchdog) {
        while (!(Test-Path -LiteralPath (Join-Path $script:run 'cleanup-complete.txt'))) {
            $owner=Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue
            if (!$owner -or $owner.StartTime.ToUniversalTime().Ticks -ne $OwnerStartTicks) { break }
            Start-Sleep -Seconds 2
        }
        if (Test-Path -LiteralPath (Join-Path $script:run 'cleanup-complete.txt')) { exit 0 }
    }
    $recoveryMutex=[Threading.Mutex]::new($false,'Global\SelectiveVpn.Acceptance')
    $recoveryLocked=$false
    try {
        try { $recoveryLocked=$recoveryMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $recoveryLocked=$true }
        if (!$recoveryLocked) { throw 'An acceptance run is still active; recovery was not started' }
        try { Restore-AndStop; Write-Json 'recovery.json' @{success=$true;serviceState='Stopped'}; Event 'Recovery complete; service stopped' }
        catch { Event "RECOVERY FAILED: $_"; Write-Json 'recovery.json' @{success=$false;error=$_.Exception.Message}; try { Stop-TestService } catch { Event "STOP FAILED: $_" }; exit 2 }
    } finally { if ($recoveryLocked) {$recoveryMutex.ReleaseMutex()}; $recoveryMutex.Dispose() }
    exit 0
}

$mutex=[Threading.Mutex]::new($false,'Global\SelectiveVpn.Acceptance')
$locked=$false
try {
    try { $locked=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
    if (!$locked) { throw 'Another acceptance run is active' }
    if (!(Test-Path -LiteralPath $serviceExe)) { throw 'Installed service executable missing' }
    if (!(Test-Path -LiteralPath $settingsFile)) { throw 'Installed settings missing' }
    $svc=Get-CimInstance Win32_Service -Filter "Name='SelectiveVpn'"
    if (!$svc -or $svc.PathName.Trim('"') -ne $serviceExe) { throw 'Unexpected installed service path' }
    $curl=Join-Path $env:WINDIR 'System32\curl.exe'
    if (!(Test-Path -LiteralPath $curl)) { throw 'Windows curl.exe missing' }
    if ($CheckOnly) {
        if ((Get-Service SelectiveVpn).Status -eq 'Running') { $checkStatus=Rpc @{command='status'}; Write-Host ('Read-only RPC verified: ' + $checkStatus.state) }
        Write-Host 'CHECK ONLY OK: RPC helper compiled, service path/settings/curl found. No settings, routes or service state changed.'
        $script:exitCode=0
    } else {
        $conflict=@(Get-NetAdapter | Where-Object { $_.Name -match 'PlanetVPN' -and $_.Status -eq 'Up' })
        if ($conflict.Count) { throw 'Disconnect original PlanetVPN before running this test. Nothing changed.' }
        $pending=@(Get-ChildItem -LiteralPath $runs -Directory -ErrorAction SilentlyContinue | Where-Object { (Test-Path -LiteralPath (Join-Path $_.FullName 'original-settings.json')) -and !(Test-Path -LiteralPath (Join-Path $_.FullName 'cleanup-complete.txt')) })
        if ($pending.Count) { throw "Unfinished earlier test. Run -Recover -RunDirectory '$($pending[0].FullName)' first." }
        $script:started=[DateTimeOffset]::Now
        $script:run=Join-Path $runs ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6))
        New-Item -ItemType Directory -Path $script:run -Force | Out-Null
        # Only admin/SYSTEM can change recovery data; the current user can read/upload reports.
        Protect-Report $script:run
        $original=[IO.File]::ReadAllText($settingsFile)
        [IO.File]::WriteAllText((Join-Path $script:run 'original-settings.json'),$original,$utf8)
        $script:backupReady=$true
        $scriptPath=$PSCommandPath.Replace("'","''"); $runLiteral=$script:run.Replace("'","''")
        $ownerTicks=(Get-Process -Id $PID).StartTime.ToUniversalTime().Ticks
        $watch="& '$scriptPath' -Watchdog -RunDirectory '$runLiteral' -OwnerPid $PID -OwnerStartTicks $ownerTicks"
        $null=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($watch)))
        Event "Report directory: $script:run"
        Event 'Keep original VPN disconnected. Do not edit SelectiveVpn settings during the test. This can take several minutes.'
        Write-Json 'environment.json' ([ordered]@{
            powershell=$PSVersionTable.PSVersion.ToString()
            os=[Environment]::OSVersion.VersionString
            scriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
            serviceDllSha256=(Get-FileHash -LiteralPath (Join-Path (Split-Path $serviceExe) 'SelectiveVpn.Service.dll') -Algorithm SHA256).Hash
            windowsDllSha256=(Get-FileHash -LiteralPath (Join-Path (Split-Path $serviceExe) 'SelectiveVpn.Windows.dll') -Algorithm SHA256).Hash
        })
        Snapshot 'before'
        Stop-TestService
        $script:testSettings=$original | ConvertFrom-Json
        $script:preservedBlocks=@($script:testSettings.rules | Where-Object { $_.enabled -and $_.kind -eq 'Application' -and $_.target -eq 'Vpn' })
        $script:testSettings.autoConnect=$false
        $script:testSettings.selectedServerId='recommended'
        $script:testSettings.protocol='Auto'
        $script:testSettings.defaultRoute='Direct'
        $script:testSettings.rules=@($script:preservedBlocks)
        Write-Settings ($script:testSettings | ConvertTo-Json -Depth 32 -Compress)
        $s=Start-TestService
        Write-Json 'initial-status.json' $s
        Assert-Check 'Idle service' ($s.state -eq 'Disconnected') $s.message
        Assert-Check 'No idle TUN' (@(Get-NetAdapter | Where-Object { $_.Name -eq 'SelectiveVpn-TUN' -and $_.Status -eq 'Up' }).Count -eq 0) 'No active SelectiveVpn-TUN expected'
        $script:directProbe=Join-Path $script:run 'direct-probe.exe'
        $script:vpnProbe=Join-Path $script:run 'vpn-probe.exe'
        Copy-Item -LiteralPath $curl -Destination $script:directProbe
        Copy-Item -LiteralPath $curl -Destination $script:vpnProbe
        $base=Probe $script:directProbe 'baseline-ipv4' 'https://1.1.1.1/cdn-cgi/trace'
        $baseDomain=Probe $script:directProbe 'baseline-domain' 'https://www.cloudflare.com/cdn-cgi/trace'
        if (!$base.success -or !$baseDomain.success) { throw 'Direct baseline endpoint unavailable: cannot reliably compare routing/blocking' }
        Result 'Direct baseline' 'PASS' 'Both numeric-IP and domain endpoints reachable'
        $base6=Probe $script:directProbe 'baseline-ipv6' 'https://[2606:4700:4700::1111]/cdn-cgi/trace' '-6'
        $script:ipv6Available=$base6.success
        if (!$script:ipv6Available) { Result 'IPv6 blocking coverage' 'SKIP' 'No working direct IPv6 baseline' }
        $appRule=Rule 'Application' $script:vpnProbe
        Save-TestRules @($appRule) 'offline-policy' $false
        Check-Blocked 'Blocked while disconnected'
        $null=Rpc @{command='connect'}
        Wait-Connected 'Initial connection'
        Snapshot 'connected'
        $vpn=Probe $script:vpnProbe 'connected-protected' 'https://1.1.1.1/cdn-cgi/trace'
        $direct=Probe $script:directProbe 'connected-direct' 'https://1.1.1.1/cdn-cgi/trace'
        Assert-Check 'Application VPN route' ($vpn.success -and $vpn.ip -ne $base.ip) 'Protected probe must have a different egress IP than direct baseline'
        Assert-Check 'Default direct route' ($direct.success -and $direct.ip -eq $base.ip) 'Unlisted probe must keep baseline egress IP'
        if (!$vpn.success) { throw 'Connected status did not produce usable application HTTPS' }
        Save-TestRules @($appRule,(Rule 'DomainSuffix' 'cloudflare.com')) 'Domain connection'
        $viaDomain=Probe $script:directProbe 'domain-route' 'https://www.cloudflare.com/cdn-cgi/trace'
        $vpnReference=Probe $script:vpnProbe 'domain-reference' 'https://www.cloudflare.com/cdn-cgi/trace'
        Assert-Check 'Domain VPN route' ($viaDomain.success -and $vpnReference.success -and $viaDomain.ip -eq $vpnReference.ip -and $viaDomain.ip -ne $baseDomain.ip) 'Domain-routed probe must match VPN egress, differ from direct'
        Save-TestRules @($appRule,(Rule 'IpCidr' '1.1.1.1/32')) 'IP connection'
        $viaIp=Probe $script:directProbe 'ip-route' 'https://1.1.1.1/cdn-cgi/trace'
        $vpnReference=Probe $script:vpnProbe 'ip-reference' 'https://1.1.1.1/cdn-cgi/trace'
        Assert-Check 'IP VPN route' ($viaIp.success -and $vpnReference.success -and $viaIp.ip -eq $vpnReference.ip -and $viaIp.ip -ne $base.ip) 'CIDR-routed probe must match VPN egress, differ from direct'
        Save-TestRules @($appRule) 'Restore direct connection'
        $direct=Probe $script:directProbe 'direct-rule-removed' 'https://1.1.1.1/cdn-cgi/trace'
        Assert-Check 'Direct route after removing destination rules' ($direct.success -and $direct.ip -eq $base.ip) 'Default direct egress restored'
        $null=Rpc @{command='disconnect'}
        Check-Blocked 'Blocked after disconnect'
        $null=Rpc @{command='connect'}
        Wait-Connected 'Connection before service stop'
        Stop-TestService
        Check-Blocked 'Blocked after service stop'
        Snapshot 'stopped'
        Assert-Check 'Service stopped during test' ((Get-Service SelectiveVpn).Status -eq 'Stopped') 'SCM state'
        Result 'UDP / reboot / every protocol' 'SKIP' 'This acceptance checks HTTPS/TCP, available IPv6, and the transport selected by Auto; not UDP or reboot behavior'
        $script:exitCode=0
    }
} catch {
    if ($script:run) { Result 'Test aborted' 'FAIL' $_.Exception.Message } else { Write-Error -Message $_.Exception.Message -ErrorAction Continue }
    $script:exitCode=1
} finally {
    if ($script:backupReady) {
        try { Restore-AndStop; Result 'Original settings and protection restored' 'PASS' 'Original settings restored exactly; service stopped' }
        catch { Result 'Cleanup' 'FAIL' $_.Exception.Message; try { Stop-TestService } catch { Event "SERVICE STOP FAILED: $_" }; $script:exitCode=2 }
        Snapshot 'final'
        Collect-Logs
        $failures=@($script:results | Where-Object { $_.result -in @('FAIL','INCONCLUSIVE') })
        if ($failures.Count -and $script:exitCode -eq 0) { $script:exitCode=1 }
        Write-Json 'summary.json' ([ordered]@{started=$script:started.ToString('o');finished=[DateTimeOffset]::Now.ToString('o');exitCode=$script:exitCode;cleanupSucceeded=$script:cleanupOk;serviceState=(Get-Service SelectiveVpn).Status.ToString();checks=$script:results.ToArray()})
        # Allowlist: never collect engine.json, transport.ovpn, provider/profile secrets, or EXEs.
        try {
            $files=@(Get-ChildItem -LiteralPath $script:run -File | Where-Object { $_.Extension -in @('.json','.txt','.log','.previous') })
            Compress-Archive -LiteralPath $files.FullName -DestinationPath ($script:run+'.zip') -Force
            Protect-Report ($script:run+'.zip') -File
            Event "RESULT ARCHIVE: $($script:run).zip"
        } catch { Event "Archive failed; report folder is available: $_" }
        Event "FINISHED: exit=$script:exitCode; restored=$script:cleanupOk; service=$((Get-Service SelectiveVpn).Status)"
    }
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
exit $script:exitCode
