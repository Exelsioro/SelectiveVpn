using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SelectiveVpn.Core;

namespace SelectiveVpn.Windows;

public sealed class EngineProcess : IDisposable
{
    public const string ExpectedSha256 = "8F30682EE198855440D2A7FE070D5D3653793B2D01BB8C85EEA88F93BBE7C8B9";
    private readonly string executable;
    private readonly SecureStore store;
    private readonly Action<string> log;
    private Process? process;
    private IntPtr job;
    private ProbeEndpoint? probe;
    private EngineDiagnostics? diagnostics;
    private Timer? diagnosticsTimer;
    private volatile string lastError = "";
    public bool Running => process is { HasExited: false };
    public string LastProbeFailure { get; private set; } = "";

    public EngineProcess(string executable, SecureStore store, Action<string> log)
    { this.executable = executable; this.store = store; this.log = log; }

    public async Task StartAsync(ClientSettings settings, ServerProfile? server, bool online, CancellationToken ct, bool tun = true, string? physicalInterface = null, string? vpnInterface = null, bool directIPv6Available = true, VpnProtocol protocol = VpnProtocol.VlessReality)
    {
        Stop();
        lastError = "";
        using (var file = File.OpenRead(executable))
            if (!Convert.ToHexString(SHA256.HashData(file)).Equals(ExpectedSha256, StringComparison.Ordinal))
                throw new InvalidDataException("SHA256 сетевого движка не совпадает с проверенной версией.");
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        probe = new(port, "health", Convert.ToHexString(RandomNumberGenerator.GetBytes(24)));
        var configPath = Path.Combine(store.Root, "engine.json");
        store.Write("engine.json", Encoding.UTF8.GetBytes(EngineConfig.Build(settings, server, online, probe, tun, physicalInterface, vpnInterface, directIPv6Available, protocol).ToJsonString()));
        var checkInfo = StartInfo("check", configPath);
        using (var check = Process.Start(checkInfo) ?? throw new InvalidOperationException("Engine check failed to start."))
        {
            var stderr = check.StandardError.ReadToEndAsync(ct);
            var stdout = check.StandardOutput.ReadToEndAsync(ct);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            try { await check.WaitForExitAsync(timeout.Token); }
            catch { check.Kill(true); throw; }
            await stdout;
            var error = await stderr;
            if (check.ExitCode != 0) throw new InvalidDataException("Ошибка проверки конфигурации движка: " + SafeError(error, server));
        }
        job = Job.Create();
        try
        {
            process = Process.Start(StartInfo("run", configPath)) ?? throw new InvalidOperationException("Engine failed to start.");
            if (!Job.AssignProcessToJobObject(job, process.Handle)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var sessionDiagnostics = diagnostics = new EngineDiagnostics(log);
            var interval = TimeSpan.FromMinutes(1);
            diagnosticsTimer = new Timer(_ => sessionDiagnostics.Flush(), null, interval, interval);
            DataReceivedEventHandler receive = (_, e) =>
            {
                if (string.IsNullOrWhiteSpace(e.Data)) return;
                var line = SafeError(e.Data, server);
                if (probe is not null) line = line.Replace(probe.Password, "<credential>", StringComparison.Ordinal);
                try { store.AppendLog("engine.log", line); } catch (IOException) { }
                if (sessionDiagnostics.Record(line)) lastError = line;
            };
            process.OutputDataReceived += receive; process.ErrorDataReceived += receive;
            store.AppendLog("engine.log", $"START pid={process.Id} tun={tun} server={server?.Id} physical={physicalInterface} vpn={vpnInterface} directIPv6={directIPv6Available} debug={settings.DiagnosticLogging}");
            process.BeginOutputReadLine(); process.BeginErrorReadLine();
            var until = DateTime.UtcNow.AddSeconds(12);
            while (DateTime.UtcNow < until)
            {
                ct.ThrowIfCancellationRequested();
                if (!Running) throw new InvalidOperationException("Сетевой движок завершился: " + lastError);
                if (!tun)
                {
                    try { using var ready = new TcpClient(); await ready.ConnectAsync(IPAddress.Loopback, port, ct); return; }
                    catch (SocketException) { }
                }
                else if (NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == Wire.InterfaceName && n.OperationalStatus == OperationalStatus.Up)) return;
                await Task.Delay(200, ct);
            }
            throw new TimeoutException("TUN-интерфейс не появился.");
        }
        catch { Stop(); throw; }
    }

    public async Task<bool> ProbeAsync(CancellationToken ct)
    {
        LastProbeFailure = "";
        if (!Running || probe is null)
        {
            LastProbeFailure = "Сетевой движок или канал проверки недоступен.";
            return false;
        }
        using var handler = new SocketsHttpHandler
        {
            Proxy = new WebProxy($"socks5://127.0.0.1:{probe.Port}") { Credentials = new NetworkCredential(probe.Username, probe.Password) },
            UseProxy = true, ConnectTimeout = TimeSpan.FromSeconds(5), AllowAutoRedirect = false
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        try
        {
            using var response = await client.GetAsync("https://www.cloudflare.com/cdn-cgi/trace", HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                LastProbeFailure = $"HTTPS-проверка www.cloudflare.com: HTTP {(int)response.StatusCode}.";
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex) when (!ct.IsCancellationRequested && ex is HttpRequestException or OperationCanceledException)
        {
            LastProbeFailure = ex is OperationCanceledException ? "HTTPS-проверка www.cloudflare.com: таймаут 8 секунд."
                : "HTTPS-проверка www.cloudflare.com: " + ex.Message;
            return false;
        }
    }

    private ProcessStartInfo StartInfo(string command, string config)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true, StandardErrorEncoding = Encoding.UTF8, StandardOutputEncoding = Encoding.UTF8, WorkingDirectory = store.Root };
        info.ArgumentList.Add(command); info.ArgumentList.Add("-c"); info.ArgumentList.Add(config);
        return info;
    }
    public static string SafeError(string error, ServerProfile? server)
    {
        error = System.Text.RegularExpressions.Regex.Replace(error, @"\x1B\[[0-?]*[ -/]*[@-~]", "");
        if (server is not null)
            foreach (var secret in new[] { server.Uuid, server.PublicKey, server.AccessKey, server.WireGuard?.PrivateKey, server.WireGuard?.PresharedKey })
                if (secret is { Length: >= 8 }) error = error.Replace(secret, "<credential>", StringComparison.Ordinal);
        return error.Length > 700 ? error[..700] : error;
    }
    public void Stop()
    {
        diagnosticsTimer?.Dispose();
        diagnosticsTimer = null;
        if (job != IntPtr.Zero) { Job.CloseHandle(job); job = IntPtr.Zero; }
        if (process is not null)
        {
            if (!process.HasExited) { process.Kill(true); process.WaitForExit(5000); }
            if (process.HasExited) process.WaitForExit();
            process.Dispose(); process = null;
        }
        diagnostics?.Flush(final: true);
        diagnostics = null;
        probe = null;
        var config = Path.Combine(store.Root, "engine.json");
        if (File.Exists(config)) File.Delete(config);
        HostNetwork.FlushDnsCache();
    }
    public void Dispose() => Stop();

    private static class Job
    {
        [StructLayout(LayoutKind.Sequential)] private struct Basic
        { public long ProcessTime, JobTime; public uint Flags; public UIntPtr Min, Max; public uint ActiveLimit; public UIntPtr Affinity; public uint Priority, Scheduling; }
        [StructLayout(LayoutKind.Sequential)] private struct Io { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
        [StructLayout(LayoutKind.Sequential)] private struct Extended { public Basic Basic; public Io Io; public UIntPtr ProcessMemory, JobMemory, PeakProcess, PeakJob; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CreateJobObjectW(IntPtr attrs, string? name);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(IntPtr job, int cls, ref Extended info, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll")] internal static extern bool CloseHandle(IntPtr handle);
        internal static IntPtr Create()
        {
            var handle = CreateJobObjectW(IntPtr.Zero, null);
            if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            var info = new Extended { Basic = new() { Flags = 0x2000 } };
            if (!SetInformationJobObject(handle, 9, ref info, (uint)Marshal.SizeOf<Extended>()))
            { int error = Marshal.GetLastWin32Error(); CloseHandle(handle); throw new Win32Exception(error); }
            return handle;
        }
    }
}
