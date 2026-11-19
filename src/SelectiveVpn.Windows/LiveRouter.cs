using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using SelectiveVpn.Core;

namespace SelectiveVpn.Windows;

public sealed class LiveRouter : IDisposable
{
    private readonly string executable;
    private readonly SecureStore store;
    private readonly EngineProcess engine;
    private readonly Action<string> log;
    private readonly ProbeEndpoint inbound = EngineProcess.AllocateProbe();
    private readonly ProbeEndpoint controller = EngineProcess.AllocateProbe();
    private readonly TcpListener acknowledgement = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stopping = new();
    private readonly Task acknowledgementTask;
    private Dictionary<string, string> appliedFiles = [];
    private string fingerprint = "";
    private string? physicalInterface;
    public ProbeEndpoint VpnEndpoint { get; } = EngineProcess.AllocateProbe();
    public ProbeEndpoint RoutingEndpoint => inbound;
    public bool Running => engine.Running;

    public LiveRouter(string executable, SecureStore store, SecureStore diagnosticsStore, Action<string> log, Func<bool>? diagnosticLogging = null)
    {
        this.executable = executable;
        this.store = store;
        this.log = log;
        engine = new(executable, store, log, diagnosticsStore, flushDnsOnStop: false, diagnosticLogging: diagnosticLogging);
        acknowledgement.Start();
        acknowledgementTask = AcknowledgeAsync(stopping.Token);
    }

    public async Task EnsureAsync(ClientSettings settings, bool requestedOnline, string? physical, bool directIPv6Available,
        CancellationToken ct, bool tun = true)
    {
        if (Running && physicalInterface == physical) return;
        engine.Stop();
        var initial = CreateFiles(settings, requestedOnline);
        foreach (var (tag, content) in initial) store.Write(tag + ".json", Encoding.UTF8.GetBytes(content));
        int acknowledgementPort = ((IPEndPoint)acknowledgement.LocalEndpoint).Port;
        try
        {
            await engine.StartAsync(settings, null, false, ct, tun: tun, fixedProbe: inbound,
                configure: endpoint => LiveRoutingConfig.Build(settings, endpoint, VpnEndpoint, acknowledgementPort,
                    controller.Port, controller.Password, physical, directIPv6Available, tun));
            await AwaitActivationAsync(initial, ct);
            appliedFiles = initial;
            fingerprint = Fingerprint(settings, requestedOnline);
            physicalInterface = physical;
        }
        catch { engine.Stop(); throw; }
        log("Постоянный маршрутизатор запущен. Прямые соединения сохраняются при переподключении VPN.");
    }

    public async Task ApplyAsync(ClientSettings settings, bool requestedOnline, CancellationToken ct)
    {
        if (!Running) throw new IOException("Постоянный маршрутизатор не запущен.");
        string nextFingerprint = Fingerprint(settings, requestedOnline);
        if (nextFingerprint == fingerprint) return;
        var next = CreateFiles(settings, requestedOnline);
        foreach (var (tag, content) in next) await ValidateAsync(tag, content, ct);
        var previous = appliedFiles;
        try
        {
            foreach (var (tag, content) in next) store.Write(tag + ".json", Encoding.UTF8.GetBytes(content));
            await AwaitActivationAsync(next, ct);
            await CloseChangedConnectionsAsync(settings, requestedOnline, ct);
            appliedFiles = next;
            fingerprint = nextFingerprint;
            log("Правила маршрутизации применены без перезапуска TUN и прямых соединений.");
        }
        catch
        {
            foreach (var (tag, content) in previous) store.Write(tag + ".json", Encoding.UTF8.GetBytes(content));
            using var rollback = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await AwaitActivationAsync(previous, rollback.Token);
            throw;
        }
    }

    private static string Fingerprint(ClientSettings settings, bool requestedOnline) =>
        string.Join('\n', LiveRoutingPolicy.Tags.Select(tag =>
            LiveRoutingPolicy.Build(settings, requestedOnline, tag, "fingerprint").ToJsonString(LiveRoutingPolicy.Json)));

    private static Dictionary<string, string> CreateFiles(ClientSettings settings, bool requestedOnline)
    {
        string revision = "r" + Guid.NewGuid().ToString("N");
        return LiveRoutingPolicy.Tags.ToDictionary(tag => tag, tag =>
            LiveRoutingPolicy.Build(settings, requestedOnline, tag, revision).ToJsonString(LiveRoutingPolicy.Json));
    }

    private async Task ValidateAsync(string tag, string content, CancellationToken ct)
    {
        string source = Path.Combine(store.Root, tag + ".candidate.json");
        string output = Path.Combine(store.Root, tag + ".candidate.srs");
        await File.WriteAllTextAsync(source, content, ct);
        try
        {
            var info = new ProcessStartInfo(executable)
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true
            };
            foreach (string arg in new[] { "rule-set", "compile", source, "--output", output }) info.ArgumentList.Add(arg);
            using var process = Process.Start(info) ?? throw new IOException("Не удалось проверить правила.");
            var error = process.StandardError.ReadToEndAsync(ct);
            var stdout = process.StandardOutput.ReadToEndAsync(ct);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(15));
            try { await process.WaitForExitAsync(deadline.Token); }
            catch { if (!process.HasExited) process.Kill(true); throw; }
            await stdout;
            string detail = await error;
            if (process.ExitCode != 0) throw new InvalidDataException("Новые правила не прошли проверку: " + detail);
        }
        finally
        {
            File.Delete(source);
            File.Delete(output);
        }
    }

    private async Task AwaitActivationAsync(Dictionary<string, string> files, CancellationToken ct)
    {
        using var handler = new SocketsHttpHandler
        {
            UseProxy = true,
            Proxy = new WebProxy($"socks5://127.0.0.1:{inbound.Port}") { Credentials = new NetworkCredential(inbound.Username, inbound.Password) }
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(1) };
        foreach (var (tag, content) in files)
        {
            var document = JsonNode.Parse(content, documentOptions: new() { MaxDepth = 8192 })!;
            string host = document["rules"]![1]!["domain"]![0]!.GetValue<string>();
            var deadline = DateTime.UtcNow.AddSeconds(15);
            bool activated = false;
            do
            {
                ct.ThrowIfCancellationRequested();
                if (!Running) throw new IOException("Маршрутизатор завершился при применении правил.");
                try
                {
                    using var response = await client.GetAsync($"http://{host}/", ct);
                    activated = response.StatusCode == HttpStatusCode.NoContent;
                    if (activated) break;
                }
                catch (Exception ex) when (!ct.IsCancellationRequested && ex is HttpRequestException or OperationCanceledException) { }
                await Task.Delay(100, ct);
            } while (DateTime.UtcNow < deadline);
            if (!activated) throw new IOException($"Маршрутизатор не подтвердил применение правил {tag}.");
        }
    }

    private async Task CloseChangedConnectionsAsync(ClientSettings settings, bool requestedOnline, CancellationToken ct)
    {
        using var handler = new SocketsHttpHandler { UseProxy = false };
        using var client = new HttpClient(handler) { BaseAddress = new Uri($"http://127.0.0.1:{controller.Port}"), Timeout = TimeSpan.FromSeconds(5) };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", controller.Password);
        string snapshot = await client.GetStringAsync("/connections", ct);
        var connections = JsonNode.Parse(snapshot)?["connections"]?.AsArray() ?? throw new InvalidDataException("Не получен список соединений маршрутизатора.");
        int changed = 0;
        foreach (var connection in connections)
        {
            var chains = connection!["chains"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();
            if (chains.Contains("control")) continue;
            var metadata = connection["metadata"]!;
            string process = metadata["processPath"]?.GetValue<string>() ?? "";
            int suffix = process.IndexOf(".exe (", StringComparison.OrdinalIgnoreCase);
            if (suffix >= 0) process = process[..(suffix + 4)];
            var target = LiveRoutingPolicy.Evaluate(settings, requestedOnline, process,
                metadata["host"]?.GetValue<string>() ?? "", metadata["destinationIP"]?.GetValue<string>() ?? "");
            if (chains.Contains("vpn") == (target == RouteTarget.Vpn)) continue;
            string id = connection["id"]!.GetValue<string>();
            using var response = await client.DeleteAsync("/connections/" + Uri.EscapeDataString(id), ct);
            if (response.StatusCode != HttpStatusCode.NotFound) response.EnsureSuccessStatusCode();
            changed++;
        }
        if (changed > 0) log($"Закрыто соединений с изменившимся маршрутом: {changed}. Остальные соединения сохранены.");
    }

    private async Task AcknowledgeAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                using var client = await acknowledgement.AcceptTcpClientAsync(ct);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(2));
                try
                {
                    var stream = client.GetStream();
                    byte[] buffer = new byte[4096];
                    int received = 0;
                    while (received < buffer.Length && buffer.AsSpan(0, received).IndexOf("\r\n\r\n"u8) < 0)
                    {
                        int count = await stream.ReadAsync(buffer.AsMemory(received), deadline.Token);
                        if (count == 0) break;
                        received += count;
                    }
                    if (buffer.AsSpan(0, received).IndexOf("\r\n\r\n"u8) < 0) continue;
                    await stream.WriteAsync("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), deadline.Token);
                }
                catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }

    public void Stop() => engine.Stop();

    public void Dispose()
    {
        engine.Dispose();
        stopping.Cancel();
        acknowledgement.Stop();
        try { acknowledgementTask.GetAwaiter().GetResult(); } catch (SocketException) { }
        stopping.Dispose();
    }
}
