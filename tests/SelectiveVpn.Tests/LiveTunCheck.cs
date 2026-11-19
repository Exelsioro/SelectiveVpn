using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using SelectiveVpn.Core;
using SelectiveVpn.Windows;

internal static class LiveTunCheck
{
    public static async Task RunAsync(string root, string output)
    {
        const string alias = "SelectiveVpn-Test";
        const string destination = "192.0.2.231";
        using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var ct = limit.Token;
        if (NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == alias))
            throw new InvalidOperationException("The isolated test interface already exists.");
        var store = new SecureStore(output);
        var settings = new ClientSettings();
        foreach (string tag in LiveRoutingPolicy.Tags)
            store.Write(tag + ".json", Encoding.UTF8.GetBytes(LiveRoutingPolicy.Build(settings, true, tag, "initial").ToJsonString(LiveRoutingPolicy.Json)));
        string exe = Path.Combine(root, "runtime", "sing-box.exe");
        using var front = new EngineProcess(exe, store, Console.WriteLine, flushDnsOnStop: false);
        using var backend = new EngineProcess(exe, new SecureStore(Path.Combine(output, "vpn")), Console.WriteLine, flushDnsOnStop: false);
        var vpnEndpoint = EngineProcess.AllocateProbe();
        var controller = EngineProcess.AllocateProbe();
        var control = EngineProcess.AllocateProbe();
        using var echoStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        using var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Start();
        int accepted = 0;
        var sources = new HashSet<string>();
        var tcpEcho = LiveRoutingCheck.EchoAsync(listener, () => Interlocked.Increment(ref accepted), echoStop.Token);
        var udpEcho = Task.Run(async () =>
        {
            try
            {
                while (!echoStop.IsCancellationRequested)
                {
                    var packet = await udpServer.ReceiveAsync(echoStop.Token);
                    sources.Add(packet.RemoteEndPoint.ToString());
                    await udpServer.SendAsync(packet.Buffer, packet.RemoteEndPoint, echoStop.Token);
                }
            }
            catch (OperationCanceledException) when (echoStop.IsCancellationRequested) { }
        }, ct);
        bool routeAdded = false;
        try
        {
            await front.StartAsync(settings, null, false, ct, tun: false, configure: endpoint =>
            {
                var config = LiveRoutingConfig.Build(settings, endpoint, vpnEndpoint, control.Port, controller.Port, controller.Password, null, true);
                var tun = config["inbounds"]![0]!;
                tun["interface_name"] = alias;
                tun["address"] = new JsonArray("172.30.252.1/30");
                tun["auto_route"] = false;
                tun["dns_mode"] = "disabled";
                var rules = config["route"]!["rules"]!.AsArray();
                rules.Insert(2, new JsonObject
                {
                    ["ip_cidr"] = destination + "/32", ["action"] = "route",
                    ["outbound"] = "control", ["override_address"] = "127.0.0.1"
                });
                return config;
            });
            await HostNetwork.PowerShellAsync(
                "if(Get-NetRoute -DestinationPrefix '" + destination + "/32' -ErrorAction SilentlyContinue) { throw 'Test route already exists' }; " +
                "$adapter=Get-NetAdapter -Name '" + alias + "' -ErrorAction Stop; " +
                "New-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '" + destination +
                "/32' -NextHop '0.0.0.0' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null", ct);
            routeAdded = true;
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Parse(destination), ((IPEndPoint)listener.LocalEndpoint).Port, ct);
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            int udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
            for (int round = 0; round < 3; round++)
            {
                await backend.StartAsync(new(), null, false, ct, tun: false, fixedProbe: vpnEndpoint);
                for (int stage = 0; stage < 2; stage++)
                {
                    if (stage == 1) backend.Stop();
                    byte[] payload = Encoding.ASCII.GetBytes($"tun-{round}-{stage}");
                    await LiveRoutingCheck.ExchangeAsync(tcp.GetStream(), payload, ct);
                    await udp.SendAsync(payload, new IPEndPoint(IPAddress.Parse(destination), udpPort), ct);
                    var reply = await udp.ReceiveAsync(ct).AsTask().WaitAsync(TimeSpan.FromSeconds(3), ct);
                    if (!reply.Buffer.SequenceEqual(payload) || !reply.RemoteEndPoint.Address.Equals(IPAddress.Parse(destination)))
                        throw new IOException("Actual TUN UDP exchange failed.");
                    if (accepted != 1) throw new IOException("Actual TUN TCP connection was recreated.");
                    foreach (string tag in LiveRoutingPolicy.Tags)
                        store.Write(tag + ".json", Encoding.UTF8.GetBytes(
                            LiveRoutingPolicy.Build(settings, true, tag, "r" + Guid.NewGuid().ToString("N")).ToJsonString(LiveRoutingPolicy.Json)));
                }
            }
            if (sources.Count != 1) throw new IOException("Actual TUN UDP association was recreated.");
            Console.WriteLine("PASS real isolated Windows TUN preserved the same TCP connection and UDP association across 3 backend restarts and rule-file updates.");
        }
        finally
        {
            try
            {
                if (routeAdded)
                    await HostNetwork.PowerShellAsync(
                        "Get-NetRoute -InterfaceAlias '" + alias + "' -DestinationPrefix '" + destination +
                        "/32' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction Stop", CancellationToken.None);
            }
            finally
            {
                front.Stop();
                echoStop.Cancel();
                await Task.WhenAll(tcpEcho, udpEcho);
            }
        }
    }
}
