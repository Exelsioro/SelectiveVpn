using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using SelectiveVpn.Core;
using SelectiveVpn.Windows;

internal static class TunCheck
{
    public static async Task RunAsync(string root)
    {
        if (Directory.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SelectiveVpn"))) throw new InvalidOperationException("Test requires no installed client state.");
        const string alias = "SelectiveVpn-Test";
        if (NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == alias && n.OperationalStatus == OperationalStatus.Up)) throw new InvalidOperationException("Test interface already active.");
        var server = PlanetProfileImporter.Import(await File.ReadAllTextAsync(Path.Combine(root, "private", "decoded-payload.json")))[0];
        string probeExe = Path.Combine(root, "tests", "SelectiveVpn.Probe", "bin", "Release", "net10.0-windows", "SelectiveVpn.Probe.exe");
        string directExe = Path.Combine(Path.GetDirectoryName(probeExe)!, "SelectiveVpn.DirectProbe.exe");
        File.Copy(probeExe, directExe, true);
        var settings = new ClientSettings { Rules =
        [new() { Kind = RuleKind.Application, Value = probeExe, Target = RouteTarget.Vpn },
         new() { Kind = RuleKind.DomainSuffix, Value = "cloudflare.com", Target = RouteTarget.Direct }] };
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        var probe = new ProbeEndpoint(port, "check", Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
        var path = Path.Combine(root, "private", "tun-test.json");
        var config = EngineConfig.Build(settings, server, true, probe);
        var tun = config["inbounds"]![0]!;
        tun["interface_name"] = alias;
        // Only the synthetic test destination range is routed. Existing default routes are untouched.
        tun["route_address"] = new JsonArray("198.18.0.0/15");
        tun["strict_route"] = false;
        tun["dns_mode"] = "disabled";
        config["experimental"]!["cache_file"]!["path"] = Path.Combine(root, "private", "tun-cache.db");
        config["log"]!["level"] = "debug";
        await File.WriteAllTextAsync(path, config.ToJsonString());
        var info = new ProcessStartInfo(Path.Combine(root, "runtime", "sing-box.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true, StandardErrorEncoding = Encoding.UTF8, StandardOutputEncoding = Encoding.UTF8 };
        foreach (var arg in new[] { "run", "-c", path }) info.ArgumentList.Add(arg);
        using var guard = new WfpGuard();
        Process? engine = null;
        Task<string>? stderr = null, stdout = null;
        try
        {
            guard.ReplaceProtectedApplications([probeExe]);
            engine = Process.Start(info)!; stderr = engine.StandardError.ReadToEndAsync(); stdout = engine.StandardOutput.ReadToEndAsync();
            var deadline = DateTime.UtcNow.AddSeconds(12);
            while (!NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == alias && n.OperationalStatus == OperationalStatus.Up))
            {
                if (engine.HasExited) throw new IOException("TUN engine exited: " + await stderr);
                if (DateTime.UtcNow > deadline) throw new TimeoutException("TUN did not start.");
                await Task.Delay(200);
            }
            var fakeIp = await ResolveFakeIp("www.cloudflare.com");
            if (!fakeIp.ToString().StartsWith("198.18.") && !fakeIp.ToString().StartsWith("198.19.")) throw new IOException("Expected FakeIP DNS response.");
            Console.WriteLine("PASS TUN starts and serves FakeIP DNS");
            await Task.Delay(1000);
            async Task<int> Fetch(string exe)
            {
                var start = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
                foreach (var arg in new[] { "--https", "www.cloudflare.com", fakeIp.ToString() }) start.ArgumentList.Add(arg);
                using var child = Process.Start(start)!; var output = child.StandardOutput.ReadToEndAsync(); await child.WaitForExitAsync();
                Console.WriteLine(Path.GetFileNameWithoutExtension(exe) + ": " + (await output).Trim()); return child.ExitCode;
            }
            if (await Fetch(probeExe) != 10) throw new IOException("Protected app was not blocked before permit.");
            Console.WriteLine("PASS protected app blocked before TUN authorization");
            guard.OpenTunnel(alias);
            if (await Fetch(probeExe) != 0) throw new IOException("Protected app failed via TUN/VPN.");
            Console.WriteLine("PASS protected application HTTPS through real TUN/VLESS");
            if (await Fetch(directExe) != 0) throw new IOException("Direct application failed via TUN routing.");
            Console.WriteLine("PASS unprotected application HTTPS with direct domain rule");
            guard.CloseTunnel();
            if (await Fetch(probeExe) != 10) throw new IOException("Closing TUN permit did not block application.");
            Console.WriteLine("PASS revoking permit blocks application while engine still runs");
        }
        finally
        {
            guard.CloseTunnel();
            if (engine is not null)
            {
                if (!engine.HasExited) engine.Kill(true);
                await engine.WaitForExitAsync(); engine.Dispose();
                if (stdout is not null) await stdout;
                if (stderr is not null)
                {
                    string log = await stderr;
                    foreach (var secret in new[] { server.Uuid, server.PublicKey, server.ShortId, probe.Password })
                        if (secret.Length > 0) log = log.Replace(secret, "<credential>", StringComparison.Ordinal);
                    await File.WriteAllTextAsync(Path.Combine(root, "artifacts", "tun-engine.log"), log);
                    Console.WriteLine("Route evidence: vpn=" + log.Contains("outbound/vless[vpn]") + " direct=" + log.Contains("outbound/direct[direct]"));
                }
            }
            guard.ReplaceProtectedApplications([]);
            File.Delete(path); File.Delete(directExe);
        }
    }

    private static async Task<IPAddress> ResolveFakeIp(string hostname)
    {
        var query = new List<byte> { 0x63, 0x71, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (string label in hostname.Split('.')) { query.Add((byte)label.Length); query.AddRange(Encoding.ASCII.GetBytes(label)); }
        query.AddRange([0, 0, 1, 0, 1]);
        using var udp = new UdpClient(); using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await udp.SendAsync(query.ToArray(), new IPEndPoint(IPAddress.Parse("172.30.251.2"), 53), timeout.Token);
        var response = (await udp.ReceiveAsync(timeout.Token)).Buffer;
        int offset = query.Count;
        int answers = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6));
        for (int i = 0; i < answers; i++)
        {
            if ((response[offset] & 0xc0) == 0xc0) offset += 2;
            else { while (response[offset] != 0) offset += response[offset] + 1; offset++; }
            int type = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset));
            int length = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(offset + 8));
            offset += 10;
            if (type == 1 && length == 4) return new IPAddress(response.AsSpan(offset, 4));
            offset += length;
        }
        throw new IOException("No DNS A answer.");
    }
}
