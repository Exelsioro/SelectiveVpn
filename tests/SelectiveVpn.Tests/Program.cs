using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using SelectiveVpn.Core;
using SelectiveVpn.Windows;

Console.OutputEncoding = System.Text.Encoding.UTF8;
if (args.Length >= 2 && args[0] == "--guard-host")
{
    using var hostGuard = new WfpGuard();
    hostGuard.ReplaceProtectedApplications([args[1]]);
    hostGuard.OpenTunnel("Loopback Pseudo-Interface 1");
    Console.WriteLine("READY");
    await Task.Delay(Timeout.Infinite);
    return;
}
int passed = 0;
void Check(bool condition, string name) { if (!condition) throw new Exception("FAILED: " + name); Console.WriteLine("PASS " + name); passed++; }
void Reject(Action action, string name) { try { action(); } catch (ArgumentException) { Check(true, name); return; } throw new Exception("FAILED: accepted " + name); }
RoutingRule Rule(RuleKind kind, string value, RouteTarget target = RouteTarget.Vpn) => new() { Kind = kind, Value = value, Target = target };
var sample = new ServerProfile("test", "Test", "192.0.2.10", 443, "9f83cd64-d79b-43dc-84f3-2c4e010f53ea", "AICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA", "abcd", "example.com", "chrome", "xtls-rprx-vision");
var settings = new ClientSettings { Rules = [Rule(RuleKind.DomainSuffix, "*.ПРИМЕР.РФ"), Rule(RuleKind.IpCidr, "203.0.113.99/24"), Rule(RuleKind.Application, @"C:\Program Files\Browser\browser.exe"), Rule(RuleKind.Domain, "example.com", RouteTarget.Direct)] };
var normalized = Policy.Normalize(settings);
Check(normalized.Rules[0].Value == "xn--e1afmkfd.xn--p1ai", "IDN / domain suffix normalization");
Check(normalized.Rules[1].Value == "203.0.113.0/24", "IPv4 subnet normalization");
Check(Policy.NormalizeCidr("2001:db8::1234/64") == "2001:db8::/64", "IPv6 subnet normalization");
Check(Policy.Ordered(normalized).First().Kind == RuleKind.Application, "VPN-only application has highest priority");
Reject(() => Policy.NormalizeDomain("https://example.com", true), "URL rejected as domain");
Reject(() => Policy.NormalizeApplication("browser.exe"), "relative executable rejected");
Reject(() => Policy.NormalizeCidr("10.0.0.1/33"), "invalid network prefix rejected");
Reject(() => Policy.Normalize(new() { Rules = [Rule(RuleKind.Domain, "EXAMPLE.COM"), Rule(RuleKind.Domain, "example.com")] }), "ambiguous duplicate rejected");
Check(!Policy.ProcessRegex(@"C:\Program Files\x.exe").Contains(@"\ "), "process regex compatible with RE2 spaces");
var probe = new ProbeEndpoint(19080, "test", "test-password");
var offline = EngineConfig.Build(settings, null, false, probe);
var online = EngineConfig.Build(settings, sample, true, probe);
var offlineRules = offline["route"]!["rules"]!.AsArray();
Check(offlineRules.First(n => n?["process_path_regex"] != null && n?["invert"] == null)!["action"]!.ToString() == "reject", "VPN app rejects when offline");
Check(offline["outbounds"]!.AsArray().All(o => o!["tag"]!.ToString() != "vpn"), "offline has no VPN fallback outbound");
Check(online["route"]!["rules"]!.AsArray().First(n => n?["process_path_regex"] != null && n?["invert"] == null)!["outbound"]!.ToString() == "vpn", "online app uses VPN exclusively");
Check(online["route"]!["rules"]!.AsArray().Any(n => n?["invert"]?.GetValue<bool>() == true && n?["action"]?.ToString() == "reject"), "unattributed traffic fails closed with protected apps");
Check(offlineRules.Any(n => n?["domain"] != null && n["outbound"]?.ToString() == "direct"), "direct domain stays direct offline");
Check(online["inbounds"]![0]!["address"]!.AsArray().Count == 2, "TUN includes IPv4 and IPv6");
Check(EngineConfig.Build(new() { DefaultRoute = RouteTarget.Vpn }, null, false, probe)["route"]!["rules"]!.AsArray().Last()!["action"]!.ToString() == "reject", "VPN default route fails closed");
var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
var engine = Path.Combine(root, "runtime", "sing-box.exe");
if (!File.Exists(engine)) throw new FileNotFoundException("Download engine before tests", engine);
var temp = Path.Combine(root, "artifacts", "checks", Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temp);
async Task CheckEngine(JsonObject config, string name)
{
    var path = Path.Combine(temp, name + ".json"); await File.WriteAllTextAsync(path, config.ToJsonString());
    var info = new ProcessStartInfo(engine) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true };
    foreach (var arg in new[] { "check", "-c", path }) info.ArgumentList.Add(arg);
    using var child = Process.Start(info)!;
    var error = child.StandardError.ReadToEndAsync(); var output = child.StandardOutput.ReadToEndAsync();
    await child.WaitForExitAsync(); await output;
    if (child.ExitCode != 0) throw new Exception("Engine config check failed: " + await error);
    Check(true, "sing-box check " + name);
    File.Delete(path);
}
await CheckEngine(offline, "offline"); await CheckEngine(online, "online");
var importedFile = Path.Combine(root, "private", "decoded-payload.json");
if (File.Exists(importedFile))
{
    var imported = PlanetProfileImporter.Import(await File.ReadAllTextAsync(importedFile));
    Check(imported.Count == 18, "18 original PlanetVPN profiles imported");
    foreach (var server in imported) await CheckEngine(EngineConfig.Build(settings, server, true, probe), "planet-" + server.Id);
}
if (args.Contains("--wfp"))
{
    if (Directory.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SelectiveVpn"))) throw new Exception("WFP integration test requires no installed client state.");
    var storePath = Path.Combine(root, "artifacts", "store-" + Guid.NewGuid().ToString("N"));
    try
    {
        var store = new SecureStore(storePath);
        store.SaveSettings(new() { SelectedServerId = "planet-persisted-selection", AutoConnect = true });
        store.SaveServers([sample]);
        var reopened = new SecureStore(storePath);
        Check(reopened.LoadSettings().SelectedServerId == "planet-persisted-selection" && reopened.LoadSettings().AutoConnect, "selected server and autoconnect survive store reopen");
        Check(reopened.LoadServers().Single() == sample, "DPAPI profiles survive store reopen");
        Check(!System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(storePath, "servers.dpapi"))).Contains(sample.Uuid), "persisted profile credentials are encrypted");
    }
    finally
    {
        if (!Path.GetFullPath(storePath).StartsWith(Path.GetFullPath(Path.Combine(root, "artifacts")) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Unsafe cleanup path.");
        if (Directory.Exists(storePath)) Directory.Delete(storePath, true);
    }
    var probeExe = Path.Combine(root, "tests", "SelectiveVpn.Probe", "bin", "Release", "net10.0-windows", "SelectiveVpn.Probe.exe");
    async Task<int> RunProbe(string ip, int port, bool udp = false)
    {
        var info = new ProcessStartInfo(probeExe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        info.ArgumentList.Add(ip); info.ArgumentList.Add(port.ToString());
        if (udp) info.ArgumentList.Add("--udp");
        using var child = Process.Start(info)!; var read = child.StandardOutput.ReadToEndAsync(); await child.WaitForExitAsync();
        Console.WriteLine("Probe " + ip + ": " + (await read).Trim()); return child.ExitCode;
    }
    var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
    var listener6 = new TcpListener(IPAddress.IPv6Loopback, 0); listener6.Start();
    int port6 = ((IPEndPoint)listener6.LocalEndpoint).Port;
    using var udp4 = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
    using var udp6 = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
    using var echoCancel = new CancellationTokenSource();
    int packets4 = 0, packets6 = 0;
    async Task Echo(UdpClient udp)
    {
        try { while (true) { var packet = await udp.ReceiveAsync(echoCancel.Token); if (ReferenceEquals(udp, udp4)) Interlocked.Increment(ref packets4); else Interlocked.Increment(ref packets6); await udp.SendAsync(packet.Buffer, packet.RemoteEndPoint, echoCancel.Token); } }
        catch (OperationCanceledException) { }
    }
    var echo4 = Echo(udp4); var echo6 = Echo(udp6);
    int udpPort4 = ((IPEndPoint)udp4.Client.LocalEndPoint!).Port, udpPort6 = ((IPEndPoint)udp6.Client.LocalEndPoint!).Port;
    try
    {
        Check(await RunProbe("127.0.0.1", port) == 0, "WFP baseline loopback reachable");
        Check(await RunProbe("1.1.1.1", 443) == 0, "WFP baseline external TCP reachable");
        Check(await RunProbe("::1", port6) == 0, "IPv6 TCP baseline");
        Check(await RunProbe("127.0.0.1", udpPort4, true) == 0, "IPv4 UDP baseline");
        Check(await RunProbe("::1", udpPort6, true) == 0, "IPv6 UDP baseline");
        using (var guard = new WfpGuard())
        {
            guard.ReplaceProtectedApplications([probeExe]);
            Check(guard.FilterCount == 8, "four persistent and four boot-time filters installed");
            if (args.Contains("--inspect"))
            {
                var pauseInfo = new ProcessStartInfo(probeExe) { UseShellExecute = false, CreateNoWindow = true };
                foreach (var a in new[] { "1.1.1.1", "443", "--hold" }) pauseInfo.ArgumentList.Add(a);
                using var paused = Process.Start(pauseInfo)!;
                await Task.Delay(1500);
                var inspectInfo = new ProcessStartInfo("netsh.exe") { UseShellExecute = false, CreateNoWindow = true };
                foreach (var a in new[] { "wfp", "show", "state", "file=" + Path.Combine(root, "artifacts", "wfp-active.xml") }) inspectInfo.ArgumentList.Add(a);
                using var inspect = Process.Start(inspectInfo)!;
                await inspect.WaitForExitAsync();
                if (!paused.HasExited) paused.Kill(true);
            }
            Check(await RunProbe("1.1.1.1", 443) == 10, "persistent application block prevents external TCP");
            Check(await RunProbe("127.0.0.1", port) == 10, "persistent application block prevents TCP");
            Check(await RunProbe("::1", port6) == 10, "persistent block prevents IPv6 TCP");
            int before4 = packets4, before6 = packets6;
            Check(await RunProbe("127.0.0.1", udpPort4, true) is 10 or 12 && packets4 == before4, "persistent block prevents IPv4 UDP delivery");
            Check(await RunProbe("::1", udpPort6, true) is 10 or 12 && packets6 == before6, "persistent block prevents IPv6 UDP delivery");
            guard.OpenTunnel("Loopback Pseudo-Interface 1");
            Check(await RunProbe("127.0.0.1", port) == 0, "dynamic permit works only on selected interface");
            Check(await RunProbe("1.1.1.1", 443) == 10, "permit for loopback does not allow external network");
            guard.CloseTunnel();
            Check(await RunProbe("127.0.0.1", port) == 10, "closing dynamic permit immediately restores block");
        }
        Check(await RunProbe("127.0.0.1", port) == 10, "block survives guard/session close");
        var hostInfo = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        hostInfo.ArgumentList.Add("--guard-host"); hostInfo.ArgumentList.Add(probeExe);
        using (var host = Process.Start(hostInfo)!)
        {
            try
            {
                if (await host.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)) != "READY") throw new Exception("Guard host failed.");
                Check(await RunProbe("127.0.0.1", port) == 0, "guard subprocess grants temporary permit");
                host.Kill(true); await host.WaitForExitAsync();
                int outcome = 0;
                for (int i = 0; i < 10 && outcome != 10; i++) { await Task.Delay(200); outcome = await RunProbe("127.0.0.1", port); }
                Check(outcome == 10, "controller crash removes permit and retains persistent block");
            }
            finally { if (!host.HasExited) { host.Kill(true); await host.WaitForExitAsync(); } }
        }
        WfpGuard.RemoveProtection();
        using (var guard = new WfpGuard()) Check(guard.FilterCount == 0, "boot and persistent filters both removed");
        Check(await RunProbe("127.0.0.1", port) == 0, "explicit removal restores connectivity");
    }
    finally { WfpGuard.RemoveProtection(); listener.Stop(); listener6.Stop(); echoCancel.Cancel(); await Task.WhenAll(echo4, echo6); }
}
if (args.Contains("--remote")) await RemoteCheck.RunAsync(root);
if (args.Contains("--tun")) await TunCheck.RunAsync(root);
Console.WriteLine($"{passed} checks passed.");
