#Requires -Version 5.1
param([string]$ScriptPath)
$ErrorActionPreference='Stop'
$utf8=[Text.UTF8Encoding]::new($false)
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$functions=@('Protect-Report','Write-Json','Probe','Write-Settings','Restore-AndStop','Validate-RunPath')
foreach($node in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    if ($node.Name -in $functions) { Invoke-Expression $node.Extent.Text }
}
$passed=0
function Check($Condition,$Name) { if (!$Condition) {throw "FAILED: $Name"}; $script:passed++; Write-Host "PASS $Name" }
$fixture=Join-Path $env:TEMP ('SelectiveVpn-acceptance-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$script:run=Join-Path $fixture 'report with spaces'
$data=Join-Path $fixture 'data'
New-Item -ItemType Directory -Path $script:run,$data | Out-Null
$settingsFile=Join-Path $data 'settings.json'
$script:cleanupOk=$false
$script:state='Running'
$script:stops=0
$script:throwOnStart=$false
function Stop-TestService { $script:state='Stopped'; $script:stops++ }
function Start-TestService {
    if ($script:throwOnStart) { throw 'Injected startup failure' }
    $current=Get-Content -LiteralPath $settingsFile -Raw | ConvertFrom-Json
    Check (!$current.autoConnect) 'Recovery disables autoconnect before startup'
    $script:state='Running'
    return [pscustomobject]@{state='Disconnected';protectionActive=$true;protectedApplications=1}
}
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Threading.Tasks;
public static class AcceptanceFixture {
 public static int Serve(string body) {
   var listener=new TcpListener(IPAddress.Loopback,0); listener.Start();
   int port=((IPEndPoint)listener.LocalEndpoint).Port;
   Task.Run(() => {
     try {
       using(var client=listener.AcceptTcpClient()) {
         client.ReceiveTimeout=5000;
         var stream=client.GetStream(); var reader=new StreamReader(stream);
         while(!String.IsNullOrEmpty(reader.ReadLine())) {}
         byte[] content=Encoding.UTF8.GetBytes(body);
         byte[] header=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: "+content.Length+"\r\nConnection: close\r\n\r\n");
         stream.Write(header,0,header.Length); stream.Write(content,0,content.Length); stream.Flush();
       }
     } finally { listener.Stop(); }
   });
   return port;
 }
}
'@
try {
    if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Protect-Report $script:run
        $access=(Get-Acl -LiteralPath $script:run).Access
        Check ($access.Count -ge 3 -and (Get-Acl -LiteralPath $script:run).AreAccessRulesProtected) 'Report ACL grants admin management and user reading without inheritance'
    }
    $probe=Join-Path $script:run 'probe with spaces.exe'
    Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\curl.exe') -Destination $probe
    $port=[AcceptanceFixture]::Serve("ip=203.0.113.7`nloc=ZZ`n")
    $answer=Probe $probe 'success' "http://127.0.0.1:$port/trace"
    Check ($answer.success -and $answer.exitCode -eq 0 -and $answer.ip -eq '203.0.113.7' -and $answer.location -eq 'ZZ') 'Probe captures curl exit code and trace with spaces in EXE path'
    $port=[AcceptanceFixture]::Serve('not a trace')
    $answer=Probe $probe 'invalid-body' "http://127.0.0.1:$port/trace"
    Check (!$answer.success -and $answer.exitCode -eq 0) 'HTTP 200 without trace is not a successful route measurement'
    $socket=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
    try {
        $socket.Bind([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
        $answer=Probe $probe 'refused' ('http://127.0.0.1:'+([Net.IPEndPoint]$socket.LocalEndPoint).Port+'/trace')
        Check (!$answer.success -and $answer.exitCode -eq 7) 'Refused connection captures nonzero native exit code'
    } finally {$socket.Dispose()}
    $original='{"autoConnect":true,"rules":[{"enabled":true,"kind":"Application","target":"Vpn","value":"C:\\Original\\app.exe"}]}'
    [IO.File]::WriteAllText((Join-Path $script:run 'original-settings.json'),$original,$utf8)
    [IO.File]::WriteAllText($settingsFile,'{"autoConnect":false,"rules":[]}',$utf8)
    Restore-AndStop
    Check ($script:state -eq 'Stopped' -and $script:stops -eq 2) 'Recovery stops service before rewriting and after reapplying protection'
    Check ([IO.File]::ReadAllText($settingsFile) -ceq $original) 'Original settings including autoconnect restored exactly'
    Check ($script:cleanupOk -and (Test-Path -LiteralPath (Join-Path $script:run 'cleanup-complete.txt'))) 'Successful recovery marks completion'
    Remove-Item -LiteralPath (Join-Path $script:run 'cleanup-complete.txt')
    $script:cleanupOk=$false; $script:throwOnStart=$true; $script:state='Running'; $threw=$false
    try { Restore-AndStop } catch { $threw=$true }
    Check ($threw -and $script:state -eq 'Stopped') 'Recovery startup failure still attempts final service stop'
    Check ([IO.File]::ReadAllText($settingsFile) -ceq $original) 'Recovery startup failure still restores original settings'
    Check (!(Test-Path -LiteralPath (Join-Path $script:run 'cleanup-complete.txt'))) 'Failed policy restoration is not marked complete'
    $runs=$fixture
    Check ((Validate-RunPath $script:run) -eq $script:run) 'Recovery accepts a backed-up child directory'
    $threw=$false
    try { Validate-RunPath ([IO.Path]::GetTempPath()) | Out-Null } catch { $threw=$true }
    Check $threw 'Recovery rejects paths outside its report root'
    Write-Host "$passed checks passed. Real service, WFP and routes were not changed."
} finally {
    $full=[IO.Path]::GetFullPath($fixture)
    if (!$full.StartsWith([IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\SelectiveVpn-acceptance-test-',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsafe fixture cleanup path'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
