using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using SelectiveVpn.Core;
using SelectiveVpn.Windows;

Console.OutputEncoding = System.Text.Encoding.UTF8;
if (args.Length == 2 && args[0] == "--live-routing-tun-check")
{
    await LiveTunCheck.RunAsync(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../")), args[1]);
    return;
}
if (args.Length == 2 && args[0] == "--live-routing-check")
{
    await LiveRoutingCheck.RunAsync(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../")), args[1]);
    return;
}
if (args.Length >= 2 && args[0] == "--guard-host")
{
    using var hostGuard = new WfpGuard();
    hostGuard.ReplaceProtectedApplications([args[1]]);
    hostGuard.OpenTunnel("Loopback Pseudo-Interface 1");
    Console.WriteLine("READY");
    await Task.Delay(Timeout.Infinite);
    return;
}
if (args.Contains("--transport-check"))
{
    var repo = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../"));
    var store = new SecureStore(Path.Combine(repo, "private", "transport-check"));
    var provider = System.Text.Json.JsonSerializer.Deserialize<ProviderSettings>(await File.ReadAllTextAsync(Path.Combine(repo, "private", "provider-bootstrap.json")), Wire.Json)!;
    var profiles = args.Contains("--cached") ? store.LoadServers() : await new PlanetCatalog(provider).RefreshAsync(Console.WriteLine, CancellationToken.None);
    store.SaveServers(profiles);
    foreach (var p in profiles) Console.WriteLine($"CATALOG {p.Id} {p.Country} {string.Join(',', p.Protocols)}");
    var physical = await HostNetwork.GetPhysicalAsync(CancellationToken.None);
    using var transport = new OpenVpnProcess(Path.Combine(repo, "runtime", "openvpn", "openvpn.exe"), store, Console.WriteLine);
    using var checkEngine = new EngineProcess(Path.Combine(repo, "runtime", "sing-box.exe"), store, Console.WriteLine);
    var server = profiles.First();
    foreach (var protocol in server.Protocols)
    {
        try
        {
            string? vpn = null;
            if (protocol != VpnProtocol.VlessReality) { await transport.StartAsync(server, protocol, physical, CancellationToken.None); vpn = OpenVpnProcess.InterfaceName; }
            await checkEngine.StartAsync(new(), server, true, CancellationToken.None, tun: false, physicalInterface: physical.Name, vpnInterface: vpn);
            Console.WriteLine($"RESULT {protocol} HTTPS={await checkEngine.ProbeAsync(CancellationToken.None)}");
        }
        catch (Exception ex) { Console.WriteLine($"RESULT {protocol} ERROR={ex.Message}"); }
        finally { checkEngine.Stop(); transport.Stop(); await HostNetwork.CleanupOwnRoutesAsync(); }
    }
    return;
}
if (args.Contains("--service-check"))
{
    async Task<StatusSnapshot> Request(RpcRequest request)
    {
        var response = await PipeRpc.CallAsync(request);
        if (!response.Success) throw new Exception(response.Error);
        Console.WriteLine($"SERVICE {request.Command}: {response.Status!.State} {response.Status.Message}");
        return response.Status!;
    }
    var status = await Request(new("status"));
    Console.WriteLine("LOCATIONS " + string.Join(", ", status.Servers.Select(s => s.Name)));
    if (status.State != TunnelState.Disconnected) throw new Exception("Service should start disconnected for this validation.");
    if (System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == Wire.InterfaceName && n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)) throw new Exception("Idle service created TUN.");
    await Request(new("select-server", ServerId: "pool-54"));
    await Request(new("select-protocol", Protocol: VpnProtocol.OpenVpnTcp));
    await ServiceControl.StopAsync(); Console.WriteLine("SERVICE SCM stopped");
    await ServiceControl.StartAsync(); await Task.Delay(5000);
    status = await Request(new("status"));
    if (status.Settings.SelectedServerId != "pool-54" || status.Settings.Protocol != VpnProtocol.OpenVpnTcp) throw new Exception("Selection was lost after service restart.");
    Console.WriteLine("SERVICE server and protocol persisted");
    await Request(new("select-server", ServerId: "recommended"));
    await Request(new("select-protocol", Protocol: VpnProtocol.Auto));
    await Request(new("connect"));
    for (int i = 0; i < 45; i++)
    {
        await Task.Delay(1000); status = await Request(new("status"));
        if (status.State is TunnelState.Faulted or TunnelState.Connected) break;
    }
    bool full = args.Contains("--full");
    if (full && status.State != TunnelState.Connected) throw new Exception("Full connection did not succeed.");
    if (!full && status.State != TunnelState.Faulted) throw new Exception("Expected a clear rejection while original VPN is active.");
    await Request(new("disconnect"));
    await ServiceControl.StopAsync(); Console.WriteLine("SERVICE SCM stopped after connect attempt");
    await ServiceControl.StartAsync(); await Task.Delay(5000);
    await Request(new("status"));
    Console.WriteLine("SERVICE CHECK PASSED");
    return;
}
int passed = 0;
void Check(bool condition, string name) { if (!condition) throw new Exception("FAILED: " + name); Console.WriteLine("PASS " + name); passed++; }
void Reject(Action action, string name) { try { action(); } catch (ArgumentException) { Check(true, name); return; } throw new Exception("FAILED: accepted " + name); }
RoutingRule Rule(RuleKind kind, string value, RouteTarget target = RouteTarget.Vpn) => new() { Kind = kind, Value = value, Target = target };
int cleanupAttempts = 0;
var startupMessages = new List<string>();
await HostNetwork.RetryCleanupAsync(_ =>
{
    if (++cleanupAttempts == 1) throw new TimeoutException("temporary CIM delay");
    return Task.CompletedTask;
}, [TimeSpan.Zero, TimeSpan.Zero], startupMessages.Add, CancellationToken.None);
Check(cleanupAttempts == 2 && startupMessages.Any(message => message.Contains("temporary CIM delay", StringComparison.Ordinal)),
    "startup cleanup retries a transient timeout and reaches readiness");
cleanupAttempts = 0;
try
{
    await HostNetwork.RetryCleanupAsync(_ =>
    {
        cleanupAttempts++;
        throw new TimeoutException("persistent CIM delay");
    }, [TimeSpan.Zero, TimeSpan.Zero], _ => { }, CancellationToken.None);
    throw new Exception("FAILED: a permanent cleanup failure was treated as ready");
}
catch (IOException ex) when (ex.InnerException is TimeoutException)
{
    Check(cleanupAttempts == 3, "startup cleanup stops after the configured attempt budget");
}
using (var stopping = new CancellationTokenSource())
{
    cleanupAttempts = 0;
    try
    {
        await HostNetwork.RetryCleanupAsync(_ =>
        {
            cleanupAttempts++;
            stopping.Cancel();
            stopping.Token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }, [TimeSpan.Zero], _ => { }, stopping.Token);
        throw new Exception("FAILED: cancelled cleanup was treated as ready");
    }
    catch (OperationCanceledException) when (stopping.IsCancellationRequested)
    {
        Check(cleanupAttempts == 1, "host shutdown does not retry cancelled startup cleanup");
    }
}
try
{
    await HostNetwork.RunPowerShellAsync("Start-Sleep -Seconds 30", CancellationToken.None, "test timeout", null,
        TimeSpan.FromMilliseconds(350));
    throw new Exception("FAILED: PowerShell did not time out");
}
catch (TimeoutException ex)
{
    Check(ex.Message.Contains("test timeout", StringComparison.Ordinal) && ex.Message.Contains("PID", StringComparison.Ordinal),
        "PowerShell timeout identifies the failed operation and child process");
}
using (var stopping = new CancellationTokenSource())
{
    try
    {
        await HostNetwork.RunPowerShellAsync("Start-Sleep -Seconds 30", stopping.Token, "test stop",
            line => { if (line.Contains("PID", StringComparison.Ordinal)) stopping.Cancel(); }, TimeSpan.FromSeconds(10));
        throw new Exception("FAILED: PowerShell ignored the external stop token");
    }
    catch (OperationCanceledException) when (stopping.IsCancellationRequested)
    {
        Check(true, "external stop cancels PowerShell without reporting a timeout");
    }
}
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
var notices = new List<string>();
var diagnostics = new EngineDiagnostics(notices.Add);
const string timestamp = "+0300 2026-11-16 04:35:35 ";
const string directTimeout = "ERROR [7 5.0s] connection: open connection to 203.0.113.5:6881 using outbound/direct[direct]: dial tcp 203.0.113.5:6881: i/o timeout";
diagnostics.Record(timestamp + "DEBUG [7 2ms] dns: exchanged example.com NOERROR 297");
diagnostics.Record(timestamp + "INFO [7 0ms] router: found process path: " + @"C:\Example\utweb.exe");
for (int i = 0; i < 500; i++) diagnostics.Record(timestamp + directTimeout);
Check(notices.Count == 0, "DNS success and routine direct timeouts do not flood service events");
diagnostics.Record(timestamp + directTimeout.Replace("direct[direct]", "direct[vpn]", StringComparison.Ordinal));
diagnostics.Record("FATAL[0000] engine could not start");
Check(notices.Count == 2, "VPN error and fatal engine error are published immediately");
diagnostics.Flush();
diagnostics.Flush();
Check(notices.Count == 3 && notices[2].Contains("utweb.exe: 500", StringComparison.Ordinal),
    "direct TCP timeouts produce one summary with the originating process");
const string emptyLookup = "ERROR [8 1ms] connection: open connection to ipv6.example.test:80 using outbound/direct[direct]: lookup ipv6.example.test: empty result";
for (int i = 0; i < 100; i++) diagnostics.Record(timestamp + emptyLookup);
Check(notices.Count == 3, "repeated empty direct DNS answers do not flood service events");
diagnostics.Flush();
diagnostics.Flush();
Check(notices.Count == 4 && notices[3].Contains("100", StringComparison.Ordinal),
    "empty direct DNS answers produce one counted summary");
diagnostics.Record(timestamp + emptyLookup.Replace("direct[direct]", "direct[vpn]", StringComparison.Ordinal));
Check(notices.Count == 5, "VPN DNS failures remain visible immediately");
var resolverNotices = new List<string>();
var resolverDiagnostics = new EngineDiagnostics(resolverNotices.Add);
resolverDiagnostics.Record(timestamp + "DEBUG [501 1ms] router: match[7] domain_regex=.+ && !(rule_set=resolve-vpn) => resolve(dns-direct,ipv4_only)");
resolverDiagnostics.Record(timestamp + "ERROR [501 1ms] dns: lookup failed for ipv6.example.test: empty result");
resolverDiagnostics.Record(timestamp + "ERROR [501 1ms] router: lookup ipv6.example.test: empty result");
Check(resolverNotices.Count == 0, "new DNS/router formats are summarized only for confirmed direct resolution");
resolverDiagnostics.Flush();
resolverDiagnostics.Flush();
Check(resolverNotices.Count == 1 && resolverNotices[0].Contains(": 1 ", StringComparison.Ordinal),
    "DNS and router reports for one failed lookup count as one request");
resolverDiagnostics.Record(timestamp + "DEBUG [502 1ms] router: match[6] rule_set=resolve-vpn => resolve(dns-vpn,prefer_ipv4)");
resolverDiagnostics.Record(timestamp + "ERROR [502 1ms] dns: lookup failed for example.test: empty result");
resolverDiagnostics.Record(timestamp + "ERROR [502 1ms] router: lookup example.test: empty result");
Check(resolverNotices.Count == 3, "VPN empty DNS results remain visible in both new formats");
resolverDiagnostics.Record(timestamp + "ERROR [503 1ms] dns: lookup failed for unknown.test: empty result");
Check(resolverNotices.Count == 4, "DNS failures with no known route remain visible");
resolverDiagnostics.Record(timestamp + "DEBUG [504 1ms] router: match[7] domain_regex=.+ && !(rule_set=resolve-vpn) => resolve(dns-direct,ipv4_only)");
resolverDiagnostics.Record(timestamp + "ERROR [504 1ms] router: lookup example.test: SERVFAIL");
Check(resolverNotices.Count == 5, "real direct DNS server failures remain visible");
var probe = new ProbeEndpoint(19080, "test", "test-password");
var offline = EngineConfig.Build(settings, null, false, probe);
var online = EngineConfig.Build(settings, sample, true, probe);
var offlineRules = offline["route"]!["rules"]!.AsArray();
Check(offlineRules.First(n => n?["process_path_regex"] != null && n?["invert"] == null)!["action"]!.ToString() == "reject", "VPN app rejects when offline");
Check(offline["outbounds"]!.AsArray().All(o => o!["tag"]!.ToString() != "vpn"), "offline has no VPN fallback outbound");
Check(online["route"]!["rules"]!.AsArray().First(n => n?["process_path_regex"] != null && n?["invert"] == null)!["outbound"]!.ToString() == "vpn", "online app uses VPN exclusively");
Check(online["route"]!["rules"]!.AsArray().Any(n => n?["invert"]?.GetValue<bool>() == true && n?["outbound"]?.ToString() == "vpn"), "unattributed traffic uses VPN, never direct, with protected apps");
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
var ovpnProvider = """
    client
    dev tun
    proto tcp-client
    remote ovpn.example 443
    auth-user-pass
    redirect-gateway def1
    <ca>
    TEST CA
    </ca>
    """;
Check(ServerProfiles.NeedsOpenVpnCredentials(ovpnProvider), "OpenVPN import recognizes interactive authentication");
var externalOpenVpn = ServerProfiles.Import(ovpnProvider, ".ovpn", "External OpenVPN", "test-user", "test-pass").Single();
Check(externalOpenVpn.Protocols.SequenceEqual([VpnProtocol.OpenVpnTcp])
    && externalOpenVpn.Port == 443
    && externalOpenVpn.OpenVpnConfigs[VpnProtocol.OpenVpnTcp].Contains("<auth-user-pass>", StringComparison.Ordinal)
    && !externalOpenVpn.OpenVpnConfigs[VpnProtocol.OpenVpnTcp].Contains("redirect-gateway", StringComparison.Ordinal),
    "OpenVPN profile selects TCP, adds inline credentials and ignores global routes");
Reject(() => ServerProfiles.Import(ovpnProvider, ".ovpn", "Requires login"), "OpenVPN rejects missing interactive credentials");
try
{
    ServerProfiles.Import(ovpnProvider + "\nup unsafe-script", ".ovpn", "Unsafe", "test-user", "test-pass");
    throw new Exception("FAILED unsafe OpenVPN configuration accepted");
}
catch (InvalidDataException) { Check(true, "OpenVPN importer does not allow script directives"); }

string wgKey1 = Convert.ToBase64String(Enumerable.Repeat((byte)7, 32).ToArray());
string wgKey2 = Convert.ToBase64String(Enumerable.Repeat((byte)13, 32).ToArray());
var wgProvider = $"""
    [Interface]
    PrivateKey = {wgKey1}
    Address = 10.17.1.9/24, fd00:1234::9/64
    DNS = 10.17.1.1
    MTU = 1360
    [Peer]
    PublicKey = {wgKey2}
    AllowedIPs = 0.0.0.0/0, ::/0
    Endpoint = wg.example:51820
    PersistentKeepalive = 25
    """;
var externalWireGuard = ServerProfiles.Import(wgProvider, ".conf", "External WireGuard").Single();
Check(externalWireGuard.Protocols.SequenceEqual([VpnProtocol.WireGuard])
    && externalWireGuard.WireGuard?.Addresses.First() == "10.17.1.9/24"
    && externalWireGuard.WireGuard?.KeepaliveSeconds == 25,
    "WireGuard import preserves the interface address and peer settings");
Reject(() => ServerProfiles.Import(wgProvider.Replace("[Peer]", "PostUp = unsafe-script\n[Peer]"), ".conf", "Unsafe"),
    "WireGuard importer rejects script hooks");
var catalogProfile = sample with { Id = "pool-54", PoolId = 54 };
var saved = ServerProfiles.Merge([externalOpenVpn, catalogProfile], [externalWireGuard]);
var updatedCatalog = ServerProfiles.Merge(saved, [catalogProfile with { Name = "Updated" }]);
Check(updatedCatalog.Select(profile => profile.Id).SequenceEqual(saved.Select(profile => profile.Id))
    && updatedCatalog[1].Name == "Updated", "PlanetVPN refresh preserves imported entries and list order");
Check(!ServerProfiles.Merge(saved, [catalogProfile], [54]).Any(profile => profile.PoolId == 54),
    "a manually deleted PlanetVPN location stays hidden");
Check(ServerProfiles.Import(wgProvider, ".conf", "External WireGuard").Single().Id == externalWireGuard.Id,
    "reimport updates an existing profile without duplicating it");
var wireGuardConfig = EngineConfig.Build(settings, externalWireGuard, true, probe, protocol: VpnProtocol.WireGuard);
Check(wireGuardConfig["endpoints"]![0]!["tag"]?.ToString() == "vpn"
    && wireGuardConfig["route"]!["rules"]![0]!["action"]?.ToString() == "reject",
    "WireGuard is routed as a VPN endpoint with new peer-initiated traffic blocked");
await CheckEngine(wireGuardConfig, "wireguard-import");

var domainOnly = EngineConfig.Build(new() { Rules = [Rule(RuleKind.DomainSuffix, "chatgpt.com")] }, sample, true, probe);
var domainDns = domainOnly["dns"]!["rules"]!.AsArray();
Check(domainDns.Count == 3
    && domainDns[0]!["domain_suffix"]![0]!.ToString() == "chatgpt.com"
    && domainDns[0]!["server"]!.ToString() == "fakeip"
    && domainDns[1]!["query_type"]![0]!.ToString() == "AAAA"
    && domainDns[1]!["server"]!.ToString() == "dns-direct"
    && domainDns[2]!["server"]!.ToString() == "fakeip",
    "direct AAAA uses real DNS while VPN domains and IPv4 retain synthetic addresses");
Check(online["dns"]!["rules"]!.AsArray().Count == 1, "application and CIDR rules retain synthetic IPv6");
await CheckEngine(domainOnly, "domain-only-direct-ipv6");
var unavailableIPv6 = EngineConfig.Build(new()
{
    Rules = [Rule(RuleKind.DomainSuffix, "chatgpt.com"), Rule(RuleKind.Domain, "direct.example", RouteTarget.Direct)]
}, sample, true, probe, directIPv6Available: false);
var unavailableDns = unavailableIPv6["dns"]!["rules"]!.AsArray();
Check(unavailableDns[0]!["server"]?.ToString() == "fakeip"
    && unavailableDns[1]!["action"]?.ToString() == "predefined"
    && unavailableDns[2]!["action"]?.ToString() == "predefined"
    && unavailableDns[2]!["rcode"]?.ToString() == "NOERROR"
    && unavailableDns[3]!["server"]?.ToString() == "fakeip",
    "unavailable direct IPv6 only suppresses AAAA for direct domains");
Check(unavailableIPv6["outbounds"]![0]!["domain_resolver"]!["strategy"]?.ToString() == "ipv4_only"
    && unavailableIPv6["outbounds"]![1]!["domain_resolver"] is null,
    "unavailable direct IPv6 limits DNS resolution for the direct outbound only");
await CheckEngine(unavailableIPv6, "unavailable-direct-ipv6");
var offlineDomainSettings = settings with { BlockVpnDomainsWhenDisconnected = true };
Check(!settings.NeedsDisconnectedDomainFilter && offlineDomainSettings.NeedsDisconnectedDomainFilter
    && !(offlineDomainSettings with { Rules = [Rule(RuleKind.Application, @"C:\Browser\browser.exe")] }).NeedsDisconnectedDomainFilter,
    "offline filter is opt-in and requires an enabled VPN domain");
var offlineDomainFilter = EngineConfig.Build(offlineDomainSettings, null, false, probe);
var filterRules = offlineDomainFilter["route"]!["rules"]!.AsArray();
Check(filterRules.Any(rule => rule?["domain_suffix"]?[0]?.ToString() == "xn--e1afmkfd.xn--p1ai"
    && rule["action"]?.ToString() == "reject")
    && filterRules.Last()!["outbound"]?.ToString() == "direct"
    && !filterRules.Any(rule => rule?["invert"]?.GetValue<bool>() == true),
    "offline filter rejects VPN domains and preserves the direct fallback");
await CheckEngine(offlineDomainFilter, "disabled-vpn-domain-filter");

var bound = EngineConfig.Build(settings, sample, true, probe, tun: false, physicalInterface: "Ethernet");
Check(bound["inbounds"]!.AsArray().All(n => n!["type"]!.ToString() != "tun"), "preflight cannot install a TUN");
Check(bound["outbounds"]![0]!["bind_interface"]!.ToString() == "Ethernet" && bound["outbounds"]![1]!["bind_interface"]!.ToString() == "Ethernet", "both direct and VLESS sockets bind physical interface");
await CheckEngine(bound, "preflight-bound");
await CheckEngine(EngineConfig.Build(settings, sample, true, probe, vpnInterface: "SelectiveVpn-OpenVPN", physicalInterface: "Ethernet"), "openvpn-bound");
var ovpnText = "client\ndev tun\nproto udp\nremote 192.0.2.10 4430\npersist-tun\n<ca>\nTEST CERTIFICATE\n</ca>\n";
Check(!OpenVpnConfiguration.Validate(ovpnText).Contains("persist-tun"), "OpenVPN does not retain disconnected TUN");
foreach (string unsafeDirective in new[] { "up evil.exe", "plugin evil.dll", "config external.ovpn", "<connection>" })
{
    try { OpenVpnConfiguration.Validate(ovpnText + unsafeDirective); throw new Exception("FAILED unsafe OpenVPN directive accepted"); }
    catch (InvalidDataException) { Check(true, "reject OpenVPN " + unsafeDirective); }
}
var syntheticKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
using (var aes = System.Security.Cryptography.Aes.Create())
{
    aes.Key = syntheticKey; aes.GenerateIV();
    string iv = Convert.ToBase64String(aes.IV);
    string value = Convert.ToBase64String(aes.EncryptCbc(System.Text.Encoding.UTF8.GetBytes("{\"data\":{\"node_id\":123}}"), aes.IV));
    string mac = Convert.ToHexString(System.Security.Cryptography.HMACSHA256.HashData(syntheticKey, System.Text.Encoding.UTF8.GetBytes(iv + value))).ToLowerInvariant();
    string Encode(string signature) => new JsonObject { ["payload"] = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(new JsonObject { ["iv"] = iv, ["value"] = value, ["mac"] = signature }.ToJsonString())) }.ToJsonString();
    Check(PlanetApiCodec.Decode(Encode(mac), Convert.ToBase64String(syntheticKey))["data"]!["node_id"]!.GetValue<int>() == 123, "authenticated API envelope decrypted");
    try { PlanetApiCodec.Decode(Encode(new string('0', 64)), Convert.ToBase64String(syntheticKey)); throw new Exception("FAILED invalid MAC accepted"); }
    catch (InvalidDataException) { Check(true, "tampered API envelope rejected"); }
}
var roundtrip = System.Text.Json.JsonSerializer.Deserialize<ClientSettings>(System.Text.Json.JsonSerializer.Serialize(new ClientSettings { SelectedServerId = "recommended", Protocol = VpnProtocol.OpenVpnXorTcp }, Wire.Json), Wire.Json)!;
Check(roundtrip.SelectedServerId == "recommended" && roundtrip.Protocol == VpnProtocol.OpenVpnXorTcp, "recommended selection and protocol serialize together");
Check(online["route"]!["rules"]!.AsArray().Where(n => n?["action"]?.ToString() == "resolve").All(n => n?["domain_regex"] is not null), "numeric destinations bypass DNS resolve action before CIDR");
await CheckEngine(EngineConfig.Build(settings with { DiagnosticLogging = true }, sample, true, probe), "debug-routing");
Check(EngineConfig.Build(settings with { DiagnosticLogging = true }, sample, true, probe)["log"]!["level"]!.ToString() == "debug", "diagnostic routing verbosity enabled");
var logonSettings = Wire.Clone(new ClientSettings { ConnectOnLogon=true, AutoConnect=false, DiagnosticLogging=true });
Check(logonSettings.ConnectOnLogon && !logonSettings.AutoConnect && logonSettings.DiagnosticLogging, "logon and service startup settings remain independent");
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
        Check(System.Text.Json.JsonSerializer.Serialize(reopened.LoadServers().Single(), Wire.Json) == System.Text.Json.JsonSerializer.Serialize(sample, Wire.Json), "DPAPI profiles survive store reopen");
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
