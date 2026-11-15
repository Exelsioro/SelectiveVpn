using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using SelectiveVpn.Core;

internal static class RemoteCheck
{
    public static async Task RunAsync(string root)
    {
        var servers = PlanetProfileImporter.Import(await File.ReadAllTextAsync(Path.Combine(root, "private", "decoded-payload.json")));
        var engine = Path.Combine(root, "runtime", "sing-box.exe");
        var directory = Path.Combine(root, "private", "remote-check"); Directory.CreateDirectory(directory);
        int successful = 0;
        foreach (var server in servers.Take(3))
        {
            var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
            var probe = new ProbeEndpoint(port, "check", Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
            var config = EngineConfig.Build(new(), server, true, probe, tun: false);
            var path = Path.Combine(directory, "probe.json"); await File.WriteAllTextAsync(path, config.ToJsonString());
            var info = new ProcessStartInfo(engine) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true };
            foreach (var arg in new[] { "run", "-c", path }) info.ArgumentList.Add(arg);
            using var process = Process.Start(info)!;
            var stderr = process.StandardError.ReadToEndAsync(); var stdout = process.StandardOutput.ReadToEndAsync();
            try
            {
                await Task.Delay(1000);
                using var handler = new SocketsHttpHandler
                {
                    Proxy = new WebProxy($"socks5://127.0.0.1:{port}") { Credentials = new NetworkCredential(probe.Username, probe.Password) },
                    ConnectTimeout = TimeSpan.FromSeconds(7), UseProxy = true
                };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(12) };
                using var response = await client.GetAsync("https://www.cloudflare.com/cdn-cgi/trace");
                response.EnsureSuccessStatusCode();
                string trace = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"PASS remote HTTPS via Planet node {server.Id}; " + string.Join(" ", trace.Split('\n').Where(l => l.StartsWith("ip=") || l.StartsWith("loc="))));
                successful++;
                await File.WriteAllTextAsync(Path.Combine(root, "private", "verified-server.txt"), server.Id);
                break;
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
            { Console.WriteLine($"Remote node {server.Id}: {ex.GetType().Name}: {ex.Message}"); }
            finally
            {
                if (!process.HasExited) process.Kill(true);
                await process.WaitForExitAsync(); await stdout;
                var diagnostics = await stderr;
                foreach (var credential in new[] { server.Uuid, server.PublicKey, server.ShortId, probe.Password })
                    if (!string.IsNullOrEmpty(credential)) diagnostics = diagnostics.Replace(credential, "<credential>", StringComparison.Ordinal);
                if (successful == 0) Console.WriteLine(diagnostics.Length > 1500 ? diagnostics[^1500..] : diagnostics);
                File.Delete(path);
            }
        }
        if (successful == 0) throw new IOException("No live HTTPS tunnel confirmed for the first three original profiles.");
    }
}
