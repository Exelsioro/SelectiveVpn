using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using SelectiveVpn.Core;
using SelectiveVpn.Windows;

internal static class LiveRoutingCheck
{
    public static async Task RunAsync(string root, string output)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var ct = limit.Token;
        var mainStore = new SecureStore(output);
        string executable = Path.Combine(root, "runtime", "sing-box.exe");
        using var router = new LiveRouter(executable, new SecureStore(Path.Combine(output, "router")), mainStore, Console.WriteLine);
        using var backend = new EngineProcess(executable, new SecureStore(Path.Combine(output, "vpn")), Console.WriteLine, mainStore, flushDnsOnStop: false);
        using var echoStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var directServer = new TcpListener(IPAddress.Loopback, 0);
        using var vpnServer = new TcpListener(IPAddress.Parse("127.0.0.2"), 0);
        using var datagrams = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        directServer.Start(); vpnServer.Start();
        int accepts = 0, vpnAccepts = 0;
        var udpSources = new HashSet<string>();
        var directEcho = EchoAsync(directServer, () => Interlocked.Increment(ref accepts), echoStop.Token);
        var vpnEcho = EchoAsync(vpnServer, () => Interlocked.Increment(ref vpnAccepts), echoStop.Token);
        var udpEcho = Task.Run(async () =>
        {
            try
            {
                while (!echoStop.IsCancellationRequested)
                {
                    var packet = await datagrams.ReceiveAsync(echoStop.Token);
                    lock (udpSources) udpSources.Add(packet.RemoteEndPoint.ToString());
                    await datagrams.SendAsync(packet.Buffer, packet.RemoteEndPoint, echoStop.Token);
                }
            }
            catch (OperationCanceledException) when (echoStop.IsCancellationRequested) { }
        }, ct);
        var settings = new ClientSettings
        {
            Rules = [new RoutingRule { Kind = RuleKind.IpCidr, Value = "127.0.0.2/32", Target = RouteTarget.Vpn }]
        };
        int directPort = ((IPEndPoint)directServer.LocalEndpoint).Port;
        int vpnPort = ((IPEndPoint)vpnServer.LocalEndpoint).Port;
        int udpPort = ((IPEndPoint)datagrams.Client.LocalEndPoint!).Port;

        async Task StartBackend()
        {
            await backend.StartAsync(new(), null, false, ct, tun: false, fixedProbe: router.VpnEndpoint, configure: endpoint =>
            {
                var config = EngineConfig.Build(new(), null, false, endpoint, tun: false);
                config["route"]!["rules"] = new JsonArray(new JsonObject { ["action"] = "route", ["outbound"] = "direct" });
                return config;
            });
        }

        try
        {
            await router.EnsureAsync(settings, true, null, true, ct, tun: false);
            await StartBackend();
            using var direct = await ConnectAsync(router.RoutingEndpoint, IPAddress.Loopback, directPort, ct);
            using var udpControl = await AuthenticateAsync(router.RoutingEndpoint, ct);
            var relay = await CommandAsync(udpControl.GetStream(), 3, IPAddress.Any, 0, ct);
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int exchanges = 0;
            async Task CheckDirect()
            {
                byte[] message = Encoding.ASCII.GetBytes("direct-" + ++exchanges);
                await ExchangeAsync(direct.GetStream(), message, ct);
                byte[] frame = [0, 0, 0, 1, 127, 0, 0, 1, (byte)(udpPort >> 8), (byte)udpPort, .. message];
                await udp.SendAsync(frame, relay, ct);
                var response = await udp.ReceiveAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(3), ct);
                if (!response.Buffer.AsSpan(10).SequenceEqual(message)) throw new IOException("Direct UDP data mismatch.");
                if (accepts != 1) throw new IOException("Direct TCP connection was recreated.");
            }

            await CheckDirect();
            using var vpnConnection = await ConnectAsync(router.RoutingEndpoint, IPAddress.Parse("127.0.0.2"), vpnPort, ct);
            await ExchangeAsync(vpnConnection.GetStream(), "vpn"u8.ToArray(), ct);
            for (int i = 0; i < 3; i++)
            {
                settings = settings with { DiagnosticLogging = !settings.DiagnosticLogging };
                await router.ApplyAsync(settings, true, ct);
                await CheckDirect();
                backend.Stop();
                await CheckDirect();
                int acceptedBefore = vpnAccepts;
                try
                {
                    using var blocked = await ConnectAsync(router.RoutingEndpoint, IPAddress.Parse("127.0.0.2"), vpnPort, ct);
                    await ExchangeAsync(blocked.GetStream(), "must-not-arrive"u8.ToArray(), ct);
                    throw new InvalidOperationException("VPN route fell back to direct.");
                }
                catch (IOException) { }
                if (vpnAccepts != acceptedBefore) throw new IOException("VPN-only data reached the server while the backend was stopped.");
                settings = settings with
                {
                    Rules = [.. settings.Rules, new RoutingRule { Kind = RuleKind.IpCidr, Value = $"203.0.113.{i + 1}/32", Target = RouteTarget.Direct }]
                };
                await router.ApplyAsync(settings, true, ct);
                await CheckDirect();
                await StartBackend();
                await CheckDirect();
            }
            using var beforeChange = await ConnectAsync(router.RoutingEndpoint, IPAddress.Parse("127.0.0.2"), vpnPort, ct);
            await ExchangeAsync(beforeChange.GetStream(), "before"u8.ToArray(), ct);
            settings.Rules[0].Target = RouteTarget.Direct;
            await router.ApplyAsync(settings, true, ct);
            backend.Stop();
            using var afterChange = await ConnectAsync(router.RoutingEndpoint, IPAddress.Parse("127.0.0.2"), vpnPort, ct);
            await ExchangeAsync(afterChange.GetStream(), "after"u8.ToArray(), ct);
            await CheckDirect();
            byte[] end = new byte[1];
            try
            {
                if (await beforeChange.GetStream().ReadAsync(end, ct).AsTask().WaitAsync(TimeSpan.FromSeconds(2), ct) != 0)
                    throw new InvalidOperationException("Old VPN connection remained usable after changing its route.");
            }
            catch (IOException) { }
            lock (udpSources)
                if (udpSources.Count != 1) throw new IOException("Direct UDP association was recreated.");
            var manyRules = Enumerable.Range(0, 1000).Select(i => new RoutingRule
            {
                Kind = RuleKind.IpCidr, Value = $"198.51.{i / 256}.{i % 256}/32",
                Target = i % 2 == 0 ? RouteTarget.Vpn : RouteTarget.Direct
            }).ToList();
            await router.ApplyAsync(new ClientSettings { Rules = manyRules }, true, ct);
            await CheckDirect();
            Console.WriteLine("PASS all 1000 supported rules compile and activate without dropping direct TCP/UDP.");

            var appSettings = new ClientSettings
            {
                Rules =
                [
                    new RoutingRule { Kind = RuleKind.IpCidr, Value = "127.0.0.1/32", Target = RouteTarget.Vpn },
                    new RoutingRule { Kind = RuleKind.Application, Value = Environment.ProcessPath!, Target = RouteTarget.Direct }
                ]
            };
            await router.ApplyAsync(appSettings, true, ct);
            await CheckDirect();
            Console.WriteLine("PASS direct application priority overrides a VPN IP rule in the running router.");
            Console.WriteLine($"PASS same TCP socket and UDP association survived {exchanges} exchanges, live policy changes and 3 VPN restarts.");
            Console.WriteLine("PASS VPN-only route failed closed while backend was stopped.");
            Console.WriteLine("PASS route changes close affected connections and preserve unaffected direct traffic.");
        }
        finally
        {
            echoStop.Cancel();
            await Task.WhenAll(directEcho, vpnEcho, udpEcho);
        }
    }

    internal static async Task EchoAsync(TcpListener listener, Action accepted, CancellationToken ct)
    {
        var sessions = new List<Task>();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                accepted();
                sessions.Add(Task.Run(async () =>
                {
                    using (client)
                    {
                        byte[] bytes = new byte[1024];
                        try
                        {
                            var stream = client.GetStream();
                            int count;
                            while ((count = await stream.ReadAsync(bytes, ct)) > 0)
                                await stream.WriteAsync(bytes.AsMemory(0, count), ct);
                        }
                        catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
                    }
                }, CancellationToken.None));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        finally { await Task.WhenAll(sessions); }
    }

    private static async Task<TcpClient> AuthenticateAsync(ProbeEndpoint proxy, CancellationToken ct)
    {
        var client = new TcpClient();
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, proxy.Port, ct);
            var stream = client.GetStream();
            await stream.WriteAsync(new byte[] { 5, 1, 2 }, ct);
            byte[] reply = new byte[2];
            await stream.ReadExactlyAsync(reply, ct);
            if (!reply.SequenceEqual(new byte[] { 5, 2 })) throw new IOException("SOCKS authentication method rejected.");
            byte[] user = Encoding.UTF8.GetBytes(proxy.Username), password = Encoding.UTF8.GetBytes(proxy.Password);
            byte[] authentication = [1, (byte)user.Length, .. user, (byte)password.Length, .. password];
            await stream.WriteAsync(authentication, ct);
            await stream.ReadExactlyAsync(reply, ct);
            if (reply[1] != 0) throw new IOException("SOCKS authentication rejected.");
            return client;
        }
        catch { client.Dispose(); throw; }
    }

    private static async Task<TcpClient> ConnectAsync(ProbeEndpoint proxy, IPAddress address, int port, CancellationToken ct)
    {
        var client = await AuthenticateAsync(proxy, ct);
        try { await CommandAsync(client.GetStream(), 1, address, port, ct); return client; }
        catch { client.Dispose(); throw; }
    }

    private static async Task<IPEndPoint> CommandAsync(NetworkStream stream, byte command, IPAddress address, int port, CancellationToken ct)
    {
        byte[] request = [5, command, 0, 1, .. address.GetAddressBytes(), (byte)(port >> 8), (byte)port];
        await stream.WriteAsync(request, ct);
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, ct);
        if (header[1] != 0) throw new IOException($"SOCKS command failed: {header[1]}.");
        int length = header[3] switch { 1 => 4, 4 => 16, _ => throw new IOException("Unsupported SOCKS reply address.") };
        byte[] endpoint = new byte[length + 2];
        await stream.ReadExactlyAsync(endpoint, ct);
        var ip = new IPAddress(endpoint.AsSpan(0, length));
        if (ip.Equals(IPAddress.Any)) ip = IPAddress.Loopback;
        return new(ip, endpoint[length] * 256 + endpoint[length + 1]);
    }

    internal static async Task ExchangeAsync(NetworkStream stream, byte[] message, CancellationToken ct)
    {
        await stream.WriteAsync(message, ct);
        byte[] response = new byte[message.Length];
        await stream.ReadExactlyAsync(response, ct).AsTask().WaitAsync(TimeSpan.FromSeconds(3), ct);
        if (!response.SequenceEqual(message)) throw new IOException("TCP payload mismatch.");
    }
}
