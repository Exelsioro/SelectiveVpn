using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SelectiveVpn.Core;

namespace SelectiveVpn.Windows;

public sealed class OpenVpnProcess : IDisposable
{
    public const string InterfaceName = "SelectiveVpn-OpenVPN";
    private readonly string executable;
    private readonly SecureStore store;
    private readonly Action<string> log;
    private Process? process;
    private readonly WintunAdapterProcess adapter = new();
    private TcpClient? management;
    private StreamWriter? writer;
    private CancellationTokenSource? managementCancel;
    private Task? readerTask;
    private string lastError = "";
    public bool Running => process is { HasExited: false };
    public OpenVpnProcess(string executable, SecureStore store, Action<string> log)
    { this.executable = executable; this.store = store; this.log = log; }

    public async Task StartAsync(ServerProfile server, VpnProtocol protocol, PhysicalNetwork physical, CancellationToken ct)
    {
        Stop();
        lastError = "";
        if (!server.OpenVpnConfigs.TryGetValue(protocol, out var text)) throw new InvalidOperationException("Сервер не поддерживает выбранный OpenVPN-протокол.");
        if (!File.Exists(executable)) throw new InvalidOperationException("Движок OpenVPN не установлен. Используйте личный комплект с OpenVPN или выберите профиль VLESS/REALITY или WireGuard.");
        string directory = Path.GetDirectoryName(executable)!;
        var hashes = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(Path.Combine(directory, "manifest.json")))!;
        foreach (var (name, expected) in hashes)
        {
            if (Path.GetFileName(name) != name) throw new InvalidDataException("Недопустимое имя компонента OpenVPN.");
            using var file = File.OpenRead(Path.Combine(directory, name));
            if (!Convert.ToHexString(SHA256.HashData(file)).Equals(expected, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("SHA256 OpenVPN не совпадает: " + name);
        }
        store.Write("transport.ovpn", Encoding.UTF8.GetBytes(OpenVpnConfiguration.Validate(text).Replace("nobind\n", "", StringComparison.Ordinal)));
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        store.Write("management.password", Encoding.ASCII.GetBytes(password + "\n"));
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = store.Root,
            RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        foreach (var arg in new[] { "--config", Path.Combine(store.Root, "transport.ovpn"), "--windows-driver", "wintun", "--dev-node", InterfaceName,
            "--route-nopull", "--route-noexec", "--script-security", "1", "--verb", "3", "--resolv-retry", "3", "--hand-window", "12",
            "--connect-retry-max", "1", "--local", physical.Address, "--lport", "0", "--management", "127.0.0.1", port.ToString(), Path.Combine(store.Root, "management.password"), "--management-hold", "--management-signal" }) info.ArgumentList.Add(arg);
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var authenticated = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var notifications = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Receive(string? line)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            line = EngineProcess.SafeError(line, server).Replace(password, "<credential>", StringComparison.Ordinal);
            if (!line.Contains("Use --help", StringComparison.Ordinal)) lastError = line;
            try { store.AppendLog("openvpn.log", line); } catch (IOException) { }
            log("OpenVPN: " + line);
            if (line.Contains("Initialization Sequence Completed", StringComparison.Ordinal)) ready.TrySetResult();
        }
        try
        {
            await adapter.StartAsync(Path.Combine(directory, "wintun.dll"), ct);
            process = Process.Start(info)!;
            process.OutputDataReceived += (_, e) => Receive(e.Data); process.ErrorDataReceived += (_, e) => Receive(e.Data);
            process.BeginOutputReadLine(); process.BeginErrorReadLine();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(25));
            while (true)
            {
                timeout.Token.ThrowIfCancellationRequested();
                if (!Running) throw new IOException("OpenVPN завершился: " + lastError);
                management = new TcpClient();
                try { await management.ConnectAsync(IPAddress.Loopback, port, timeout.Token); break; }
                catch (SocketException) { management.Dispose(); management = null; await Task.Delay(150, timeout.Token); }
            }
            writer = new StreamWriter(management.GetStream(), Encoding.ASCII, leaveOpen: true) { AutoFlush = true, NewLine = "\n" };
            managementCancel = new CancellationTokenSource();
            var reader = new StreamReader(management.GetStream(), Encoding.ASCII, leaveOpen: true);
            readerTask = Task.Run(async () =>
            {
                try { while (await reader.ReadLineAsync(managementCancel.Token) is { } line) { Receive("Management: " + line);
                    if (line.Contains("SUCCESS: password is correct", StringComparison.Ordinal)) authenticated.TrySetResult();
                    if (line.Contains("SUCCESS: real-time state notification", StringComparison.Ordinal)) notifications.TrySetResult();
                    if (line.Contains(",CONNECTED,SUCCESS,")) ready.TrySetResult();
                    if (line.Contains(",RECONNECTING,") || line.Contains("Verification Failed")) ready.TrySetException(new IOException("OpenVPN: " + line)); } }
                catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
                finally { reader.Dispose(); }
            });
            await writer.WriteLineAsync(password);
            await authenticated.Task.WaitAsync(timeout.Token);
            await writer.WriteLineAsync("state on");
            await notifications.Task.WaitAsync(timeout.Token);
            await writer.WriteLineAsync("hold release");
            while (!ready.Task.IsCompleted)
            {
                timeout.Token.ThrowIfCancellationRequested();
                if (!Running) throw new IOException("OpenVPN завершился: " + lastError);
                await Task.Delay(200, timeout.Token);
            }
            await ready.Task;
            await HostNetwork.AddOpenVpnRouteAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { var reason = lastError; Stop(); throw new TimeoutException("OpenVPN не подключился за 25 секунд. " + reason); }
        catch { Stop(); throw; }
    }
    public void Stop()
    {
        if (process is not null && !process.HasExited)
        {
            try { writer?.WriteLine("signal SIGTERM"); } catch (IOException) { }
            if (!process.WaitForExit(3000)) { process.Kill(true); process.WaitForExit(3000); }
        }
        managementCancel?.Cancel(); management?.Dispose();
        try { readerTask?.Wait(1000); } catch (AggregateException) { }
        try { writer?.Dispose(); } catch (IOException) { }
        managementCancel?.Dispose(); process?.Dispose();
        adapter.Dispose();
        writer = null; management = null; managementCancel = null; readerTask = null; process = null;
        foreach (string name in new[] { "transport.ovpn", "management.password" }) { var path = Path.Combine(store.Root, name); if (File.Exists(path)) File.Delete(path); }
    }
    public void Dispose() => Stop();
}
