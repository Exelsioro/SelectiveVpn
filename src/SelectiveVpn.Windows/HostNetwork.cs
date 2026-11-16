using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace SelectiveVpn.Windows;

public sealed record PhysicalNetwork(string Name, int Index, string Address);

public static class HostNetwork
{
    public static void RejectConflictingVpn()
    {
        var active = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up && n.Name.Contains("PlanetVPN", StringComparison.OrdinalIgnoreCase));
        if (active is not null) throw new InvalidOperationException($"Работает другой VPN ({active.Name}). Отключите его перед подключением SelectiveVpn. Сеть не изменена.");
    }
    public static async Task<PhysicalNetwork> GetPhysicalAsync(CancellationToken ct)
    {
        string json = await PowerShellAsync("$items = foreach($a in Get-NetAdapter -Physical | Where-Object Status -eq 'Up') { $r = Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1; $ip = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1; if($r -and $ip) { [pscustomobject]@{Name=$a.Name;Index=[int]$a.ifIndex;Address=$ip.IPAddress;Metric=$r.RouteMetric + (Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4).InterfaceMetric} } }; $items | Sort-Object Metric | Select-Object -First 1 Name,Index,Address | ConvertTo-Json -Compress", ct);
        return JsonSerializer.Deserialize<PhysicalNetwork>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? throw new IOException("Не найдено основное подключение с IPv4-шлюзом.");
    }
    public static async Task<bool> CanReachPublicIPv6Async(PhysicalNetwork physical, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name == physical.Name);
            var properties = adapter?.GetIPProperties();
            var ipv6 = properties?.GetIPv6Properties();
            if (ipv6 is null || !properties!.UnicastAddresses.Any(entry =>
                entry.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
                (entry.Address.GetAddressBytes()[0] & 0xe0) == 0x20))
                return false;

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            var cloudflare = ProbeIPv6Async(IPAddress.Parse("2606:4700:4700::1111"), ipv6.Index, timeout.Token);
            var google = ProbeIPv6Async(IPAddress.Parse("2001:4860:4860::8888"), ipv6.Index, timeout.Token);
            var pending = new List<Task<bool>> { cloudflare, google };
            while (pending.Count > 0)
            {
                var completed = await Task.WhenAny(pending);
                pending.Remove(completed);
                if (!await completed) continue;
                timeout.Cancel();
                await Task.WhenAll(pending);
                return true;
            }
            ct.ThrowIfCancellationRequested();
            return false;
        }
        catch (NetworkInformationException) { return false; }
    }

    private static async Task<bool> ProbeIPv6Async(IPAddress address, int interfaceIndex, CancellationToken ct)
    {
        // Winsock IPV6_UNICAST_IF uses the host-order IPv6 interface index.
        const SocketOptionName ipv6UnicastInterface = (SocketOptionName)31;
        using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            socket.SetSocketOption(SocketOptionLevel.IPv6, ipv6UnicastInterface, interfaceIndex);
            await socket.ConnectAsync(address, 443, ct);
            return true;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException) { return false; }
    }

    private static readonly string[] OwnInterfaces = ["SelectiveVpn-TUN", "SelectiveVpn-OpenVPN"];

    public static Task CleanupOnStartupAsync(Action<string> log, CancellationToken ct) =>
        RetryCleanupAsync(token => CleanupOwnRoutesAsync(token, log),
            [TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(5)], log, ct);

    internal static async Task RetryCleanupAsync(Func<CancellationToken, Task> cleanup,
        IReadOnlyList<TimeSpan> delays, Action<string> log, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            var watch = Stopwatch.StartNew();
            log($"Очистка сети при запуске: попытка {attempt + 1}/{delays.Count + 1}.");
            try
            {
                await cleanup(ct);
                ct.ThrowIfCancellationRequested();
                log($"Очистка сети завершена за {watch.Elapsed.TotalSeconds:F1} с.");
                return;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested && (ex is TimeoutException or IOException or NetworkInformationException))
            {
                var detail = $"Очистка сети: попытка {attempt + 1}, {watch.Elapsed.TotalSeconds:F1} с. {ex.Message}";
                if (attempt == delays.Count)
                    throw new IOException(detail + " Повторы исчерпаны.", ex);
                log(detail + $" Повтор через {delays[attempt].TotalSeconds:F0} с.");
                await Task.Delay(delays[attempt], ct);
            }
        }
    }

    public static async Task CleanupOwnRoutesAsync(CancellationToken ct = default, Action<string>? log = null)
    {
        ct.ThrowIfCancellationRequested();
        // At boot there are usually no VPN interfaces. Avoid loading the CIM modules in that case.
        if (!NetworkInterface.GetAllNetworkInterfaces().Any(adapter => OwnInterfaces.Contains(adapter.Name, StringComparer.OrdinalIgnoreCase)))
        {
            log?.Invoke("Старых VPN-адаптеров нет. Очистка маршрутов не требуется.");
            return;
        }

        const string script = """
            [Console]::Error.WriteLine('Get-NetAdapter')
            $adapters = @(Get-NetAdapter | Where-Object { $_.Name -in @('SelectiveVpn-TUN','SelectiveVpn-OpenVPN') })
            foreach ($adapter in $adapters) {
                [Console]::Error.WriteLine('Get-NetRoute / Remove-NetRoute: ' + $adapter.Name)
                Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                [Console]::Error.WriteLine('Set-DnsClientServerAddress: ' + $adapter.Name)
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction Stop
            }
            """;
        await PowerShellAsync(script, ct, "Очистка VPN-маршрутов", log);
        FlushDnsCache();
    }

    internal static void FlushDnsCache() => DnsFlushResolverCache();
    [DllImport("dnsapi.dll")] private static extern bool DnsFlushResolverCache();

    public static async Task AddOpenVpnRouteAsync(CancellationToken ct)
    {
        await PowerShellAsync("$a=Get-NetAdapter -Name 'SelectiveVpn-OpenVPN' -ErrorAction Stop; Set-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 5000; if(!(Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) { New-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -NextHop '0.0.0.0' -RouteMetric 5000 -PolicyStore ActiveStore | Out-Null }", ct);
    }
    public static Task<string> PowerShellAsync(string code, CancellationToken ct,
        string operation = "Настройка сети", Action<string>? log = null) =>
        RunPowerShellAsync(code, ct, operation, log, TimeSpan.FromSeconds(20));

    internal static async Task<string> RunPowerShellAsync(string code, CancellationToken ct,
        string operation, Action<string>? log, TimeSpan limit)
    {
        var info = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        code = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); " + code;
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(code)) }) info.ArgumentList.Add(arg);
        ct.ThrowIfCancellationRequested();
        var elapsed = Stopwatch.StartNew();
        using var process = Process.Start(info) ?? throw new IOException($"{operation}: PowerShell не запущен.");
        log?.Invoke($"{operation}: PowerShell PID {process.Id}, лимит {limit.TotalSeconds:G} с.");
        var output = process.StandardOutput.ReadToEndAsync();
        var errors = process.StandardError.ReadToEndAsync();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(limit);
        try
        {
            await process.WaitForExitAsync(timeout.Token);
            await Task.WhenAll(output, errors).WaitAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) when (process.HasExited) { }
            try { await Task.WhenAll(process.WaitForExitAsync(), output, errors).WaitAsync(TimeSpan.FromSeconds(3)); }
            catch (TimeoutException) { }
            if (ct.IsCancellationRequested)
            {
                log?.Invoke($"{operation}: отменено при остановке, PID {process.Id}, {elapsed.Elapsed.TotalSeconds:F1} с.");
                ct.ThrowIfCancellationRequested();
            }
            string trace = errors.IsCompletedSuccessfully ? LastLines(errors.Result) : "";
            throw new TimeoutException($"{operation}: PowerShell PID {process.Id}, истёк лимит {limit.TotalSeconds:G} с ({elapsed.Elapsed.TotalSeconds:F1} с). {trace}");
        }

        log?.Invoke($"{operation}: PowerShell PID {process.Id}, код {process.ExitCode}, {elapsed.Elapsed.TotalSeconds:F1} с.");
        if (process.ExitCode != 0)
            throw new IOException($"{operation}: PowerShell PID {process.Id}, код {process.ExitCode}. {LastLines(await errors)}");
        return (await output).Trim();
    }

    private static string LastLines(string text)
    {
        string tail = text.Trim();
        return tail.Length <= 800 ? tail : tail[^800..];
    }
}
