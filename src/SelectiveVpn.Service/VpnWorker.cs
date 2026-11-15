using System.Collections.Concurrent;
using SelectiveVpn.Core;
using SelectiveVpn.Windows;

namespace SelectiveVpn.Service;

public sealed class VpnWorker : BackgroundService
{
    private readonly SemaphoreSlim gate = new(1);
    private readonly ConcurrentQueue<string> events = new();
    private ClientSettings settings = new();
    private ServerProfile[] servers = [];
    private SecureStore store = null!;
    private WfpGuard guard = null!;
    private EngineProcess engine = null!;
    private OpenVpnProcess transport = null!;
    private TunnelState state = TunnelState.Starting;
    private string message = "Запуск службы";
    private CancellationToken serviceToken;
    private CancellationTokenSource? connectionCancel;
    private Task connectionTask = Task.CompletedTask;
    private bool requestedOnline;
    private VpnProtocol activeProtocol;
    private DateTime retryAt;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        serviceToken = stoppingToken;
        store = new SecureStore();
        settings = store.LoadSettings(); servers = store.LoadServers();
        using var localGuard = guard = new WfpGuard();
        using var localEngine = engine = new EngineProcess(Path.Combine(AppContext.BaseDirectory, "runtime", "sing-box.exe"), store, Log);
        using var localTransport = transport = new OpenVpnProcess(Path.Combine(AppContext.BaseDirectory, "runtime", "openvpn", "openvpn.exe"), store, Log);
        guard.ReplaceProtectedApplications(settings.ProtectedApplications);
        await HostNetwork.CleanupOwnRoutesAsync();
        SetState(TunnelState.Disconnected, "VPN отключён; сетевой движок остановлен. Защищённые приложения заблокированы.");
        if (settings.AutoConnect) QueueConnect();
        try { await Task.WhenAll(ListenAsync(stoppingToken), MonitorAsync(stoppingToken)); }
        finally
        {
            connectionCancel?.Cancel();
            try { await connectionTask; } catch (OperationCanceledException) { }
            state = TunnelState.Stopping;
            await StopNetworkAsync();
            connectionCancel?.Dispose();
        }
    }

    private async Task ListenAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await using var pipe = PipeRpc.CreateServer();
            try
            {
                await pipe.WaitForConnectionAsync(ct);
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(150));
                var request = await PipeRpc.ReadAsync<RpcRequest>(pipe, deadline.Token);
                RpcResponse response;
                if (request.Command == "status") response = new(true, Status: Snapshot());
                else
                {
                    if (request.Command is "connect" or "disconnect" or "save" or "select-server" or "select-protocol" or "refresh") connectionCancel?.Cancel();
                    await gate.WaitAsync(deadline.Token);
                    try { response = await HandleAsync(request, deadline.Token); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { Log(ex.Message); response = new(false, ex.Message, Snapshot()); }
                    finally { gate.Release(); }
                }
                await PipeRpc.WriteAsync(pipe, response, deadline.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { Log("Истёк срок запроса управления."); }
            catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or InvalidDataException) { Log("Некорректный или завершённый канал управления: " + ex.Message); }
        }
    }

    private async Task<RpcResponse> HandleAsync(RpcRequest request, CancellationToken ct)
    {
        switch (request.Command)
        {
            case "select-protocol":
                if (request.Protocol is not { } selectedProtocol || !Enum.IsDefined(selectedProtocol)) throw new ArgumentException("Неизвестный протокол.");
                var protocolSelection = settings with { Protocol = selectedProtocol };
                store.SaveSettings(protocolSelection); settings = protocolSelection;
                Log("Протокол сохранён: " + selectedProtocol);
                if (requestedOnline) QueueConnect();
                break;
            case "select-server":
                if (request.ServerId != "recommended" && !servers.Any(s => s.Id == request.ServerId)) throw new ArgumentException("Сервер не найден.");
                var selection = settings with { SelectedServerId = request.ServerId };
                store.SaveSettings(selection); settings = selection;
                Log("Выбор сервера сохранён.");
                if (requestedOnline) QueueConnect();
                break;
            case "refresh":
                var provider = store.LoadProvider() ?? throw new InvalidOperationException("Не установлен ключ формата API. Выполните обновление клиента через Install.ps1.");
                var updated = await new PlanetCatalog(provider).RefreshAsync(Log, ct);
                var merged = updated.Concat(servers.Where(s => s.PoolId is not null && updated.All(n => n.Id != s.Id))).ToArray();
                store.SaveServers(merged); servers = merged;
                if (!servers.Any(s => s.Id == settings.SelectedServerId)) settings = settings with { SelectedServerId = "recommended" };
                store.SaveSettings(settings); Log($"Каталог обновлён: {servers.Length} локаций.");
                if (requestedOnline) QueueConnect();
                break;
            case "import":
                var imported = PlanetProfileImporter.Import(request.ImportJson ?? "").ToArray();
                store.SaveServers(imported); servers = imported;
                if (!servers.Any(s => s.Id == settings.SelectedServerId)) settings = settings with { SelectedServerId = "recommended" };
                store.SaveSettings(settings); Log($"Импортировано: {servers.Length}");
                break;
            case "save":
                var next = Policy.Normalize(request.Settings ?? throw new ArgumentException("Нет настроек."));
                if (next.SelectedServerId is not (null or "recommended") && !servers.Any(s => s.Id == next.SelectedServerId)) throw new ArgumentException("Сервер не найден.");
                foreach (var rule in next.Rules.Where(r => r.Enabled && r.Kind == RuleKind.Application))
                {
                    if (!File.Exists(rule.Value)) throw new ArgumentException("Файл приложения не найден: " + rule.Value);
                    rule.Value = ApplicationPath.Canonicalize(rule.Value);
                    if (rule.Value.StartsWith(Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))! + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                        throw new ArgumentException("Компоненты самого VPN нельзя направлять в туннель.");
                }
                next = Policy.Normalize(next);
                guard.ReplaceProtectedApplications(settings.ProtectedApplications.Concat(next.ProtectedApplications));
                store.SaveSettings(next); settings = next;
                guard.ReplaceProtectedApplications(settings.ProtectedApplications);
                if (requestedOnline) QueueConnect();
                Log("Правила и протокол сохранены.");
                break;
            case "connect": QueueConnect(); break;
            case "disconnect":
                requestedOnline = false; await StopNetworkAsync();
                SetState(TunnelState.Disconnected, "VPN отключён. TUN и DNS-перехват остановлены; защищённые приложения заблокированы.");
                break;
            default: throw new ArgumentException("Неизвестная команда.");
        }
        return new(true, Status: Snapshot());
    }

    private void QueueConnect()
    {
        connectionCancel?.Cancel(); connectionCancel?.Dispose();
        connectionCancel = CancellationTokenSource.CreateLinkedTokenSource(serviceToken);
        var token = connectionCancel.Token;
        requestedOnline = true;
        SetState(TunnelState.Connecting, "Подбор и проверка подключения; сеть ещё не переключена");
        connectionTask = Task.Run(async () =>
        {
            await gate.WaitAsync(token);
            try { await ConnectAsync(token); }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            { await StopNetworkAsync(); SetState(TunnelState.Disconnected, "Подключение отменено; сетевой движок остановлен"); }
            catch (Exception ex)
            { await StopNetworkAsync(); retryAt = DateTime.UtcNow.AddSeconds(60); SetState(TunnelState.Faulted, ex.Message); }
            finally { gate.Release(); }
        }, CancellationToken.None);
    }

    private async Task ConnectAsync(CancellationToken ct)
    {
        await StopNetworkAsync(); HostNetwork.RejectConflictingVpn();
        var physical = await HostNetwork.GetPhysicalAsync(ct);
        var candidates = settings.SelectedServerId is null or "recommended"
            ? await PlanetCatalog.RankAsync(servers, settings.LastSuccessfulServerId, ct)
            : servers.Where(s => s.Id == settings.SelectedServerId).ToArray();
        if (candidates.Length == 0) throw new InvalidOperationException("Список серверов пуст. Нажмите «Обновить серверы».");
        if (settings.Protocol != VpnProtocol.Auto && candidates.All(s => !s.Protocols.Contains(settings.Protocol))) throw new InvalidOperationException("Выбранный протокол отсутствует в конфигурации сервера. Выберите другой протокол или «Авто».");
        foreach (var server in candidates)
        {
            var protocols = settings.Protocol == VpnProtocol.Auto
                ? server.Protocols.OrderBy(p => p == settings.LastSuccessfulProtocol && server.Id == settings.LastSuccessfulServerId ? -1 : (int)p).ToArray()
                : server.Protocols.Where(p => p == settings.Protocol).ToArray();
            foreach (var protocol in protocols)
            {
                ct.ThrowIfCancellationRequested();
                SetState(TunnelState.Connecting, $"Проверка {server.Name}: {protocol}");
                try
                {
                    string? vpnInterface = null;
                    if (protocol != VpnProtocol.VlessReality)
                    { await transport.StartAsync(server, protocol, physical, ct); vpnInterface = OpenVpnProcess.InterfaceName; }
                    await engine.StartAsync(settings, server, true, ct, tun: false, physicalInterface: physical.Name, vpnInterface: vpnInterface);
                    if (!await engine.ProbeAsync(ct)) throw new IOException("HTTPS через VPN недоступен.");
                    await engine.StartAsync(settings, server, true, ct, tun: true, physicalInterface: physical.Name, vpnInterface: vpnInterface);
                    if (!await engine.ProbeAsync(ct)) throw new IOException("Проверка после запуска TUN не прошла.");
                    guard.OpenTunnel(Wire.InterfaceName); activeProtocol = protocol;
                    settings = settings with { LastSuccessfulServerId = server.Id, LastSuccessfulProtocol = protocol };
                    store.SaveSettings(settings);
                    SetState(TunnelState.Connected, $"Подключено: {server.Name} · {protocol}"); return;
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                { Log($"{server.Name} / {protocol}: {EngineProcess.SafeError(ex.Message, server)}"); await StopNetworkAsync(); }
            }
        }
        throw new IOException("Серверы и протоколы не прошли проверку. Сеть восстановлена; защищённые приложения заблокированы. Причины — в журнале ниже.");
    }

    private async Task StopNetworkAsync()
    {
        guard.CloseTunnel();
        try { engine.Stop(); }
        finally { try { transport.Stop(); } finally { await HostNetwork.CleanupOwnRoutesAsync(); } }
    }

    private async Task MonitorAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        while (await timer.WaitForNextTickAsync(ct))
        {
            if (!await gate.WaitAsync(0, ct)) continue;
            try
            {
                if (state == TunnelState.Connected && (!engine.Running || (activeProtocol != VpnProtocol.VlessReality && !transport.Running) || !await engine.ProbeAsync(ct)))
                { await StopNetworkAsync(); SetState(TunnelState.Faulted, "Соединение потеряно; TUN остановлен, защищённые приложения заблокированы."); retryAt = DateTime.UtcNow.AddSeconds(30); }
                else if (state == TunnelState.Faulted && requestedOnline && DateTime.UtcNow >= retryAt) QueueConnect();
            }
            finally { gate.Release(); }
        }
    }
    private StatusSnapshot Snapshot() => new(state, message, guard.Active, settings.ProtectedApplications.Length, Wire.Clone(settings),
        new[] { new ServerInfo("recommended", "Рекомендуемый — автоматический подбор", "", 0) }.Concat(servers.Select(s => new ServerInfo(s.Id, s.Name, s.Address, s.Port, s.Protocols))).ToArray(), events.ToArray());
    private void SetState(TunnelState value, string text) { state = value; message = text; Log(text); }
    private void Log(string text)
    {
        events.Enqueue($"{DateTime.Now:HH:mm:ss} {text}"); while (events.Count > 120) events.TryDequeue(out _);
        try { store.AppendLog("service.log", text); } catch (IOException) { }
    }
}
