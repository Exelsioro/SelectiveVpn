using System.Collections.Concurrent;
using SelectiveVpn.Core;
using SelectiveVpn.Windows;

namespace SelectiveVpn.Service;

public sealed class VpnWorker(ILogger<VpnWorker> logger) : BackgroundService
{
    private readonly SemaphoreSlim gate = new(1);
    private readonly ConcurrentQueue<string> events = new();
    private ClientSettings settings = new();
    private ServerProfile[] servers = [];
    private readonly ConcurrentDictionary<string, ServerCheck> serverChecks = new(StringComparer.Ordinal);
    private string? activeServerId;
    private SecureStore store = null!;
    private WfpGuard guard = null!;
    private EngineProcess engine = null!;
    private LiveRouter router = null!;
    private OpenVpnProcess transport = null!;
    private TunnelState state = TunnelState.Starting;
    private string message = "Запуск службы";
    private CancellationToken serviceToken;
    private CancellationTokenSource? connectionCancel;
    private Task connectionTask = Task.CompletedTask;
    private bool requestedOnline;
    private volatile bool disconnectedDomainFilter;
    private VpnProtocol activeProtocol;
    private int consecutiveProbeFailures;
    private DateTime retryAt;
    private DateTimeOffset? connectedSince, lastReconnectedAt, lastFailureAt;
    private string? lastFailure;
    private int successfulConnections, reconnectAttempts, failures;
    private double totalConnectedSeconds;
    private long connectedTimestamp;
    private HashSet<int> knownSessions = [];
    private void Failure(string reason) { failures++; lastFailureAt=DateTimeOffset.UtcNow; lastFailure=reason; Log("Сбой: " + reason); }


    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await RunWorkerAsync(stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception ex) when (stoppingToken.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Ошибка при штатной остановке SelectiveVpn.");
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Служба SelectiveVpn завершилась с ошибкой. Windows может применить правила восстановления.");
            // RunWorkerAsync has already released transient network resources.
            // A normal Host shutdown would report success and prevent SCM recovery.
            Environment.Exit(1);
        }
    }

    private async Task RunWorkerAsync(CancellationToken stoppingToken)
    {
        serviceToken = stoppingToken;
        store = new SecureStore();
        try { knownSessions = LogonSessions.Read(); }
        catch (Exception ex) { Log("Не удалось прочитать сессии Windows при запуске: " + ex.Message); }
        settings = store.LoadSettings();
        servers = ServerProfiles.Merge([], store.LoadServers(), settings.DeletedPlanetPools);
        using var localGuard = guard = new WfpGuard();
        using var localEngine = engine = new EngineProcess(Path.Combine(AppContext.BaseDirectory, "runtime", "sing-box.exe"),
            new SecureStore(Path.Combine(store.Root, "vpn")), Log, store, flushDnsOnStop: false, diagnosticLogging: () => settings.DiagnosticLogging);
        using var localRouter = router = new LiveRouter(Path.Combine(AppContext.BaseDirectory, "runtime", "sing-box.exe"),
            new SecureStore(Path.Combine(store.Root, "routing")), store, Log, () => settings.DiagnosticLogging);
        using var localTransport = transport = new OpenVpnProcess(Path.Combine(AppContext.BaseDirectory, "runtime", "openvpn", "openvpn.exe"), store, Log);
        guard.ReplaceProtectedApplications(settings.ProtectedApplications);
        await HostNetwork.CleanupOnStartupAsync(Log, stoppingToken);
        stoppingToken.ThrowIfCancellationRequested();
        await ApplyRoutingAsync();
        stoppingToken.ThrowIfCancellationRequested();
        SetState(TunnelState.Disconnected, "VPN отключён. Защищённые приложения заблокированы.");
        if (settings.AutoConnect) QueueConnect();
        try { await Task.WhenAll(ListenAsync(stoppingToken), MonitorAsync(stoppingToken), MonitorLogonsAsync(stoppingToken)); }
        finally
        {
            connectionCancel?.Cancel();
            try { await connectionTask; } catch (OperationCanceledException) { }
            state = TunnelState.Stopping;
            try { await StopVpnAsync(); }
            finally { router.Stop(); await HostNetwork.CleanupOwnRoutesAsync(); }
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
                    if (request.Command is "connect" or "disconnect" or "select-server" or "select-protocol") connectionCancel?.Cancel();
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
                var selectedServer = servers.FirstOrDefault(server => server.Id == request.ServerId);
                if (request.ServerId != "recommended" && selectedServer is null) throw new ArgumentException("Сервер не найден.");
                var selectedMode = settings.Protocol;
                if (selectedServer is not null && selectedMode != VpnProtocol.Auto && !selectedServer.Protocols.Contains(selectedMode))
                    selectedMode = VpnProtocol.Auto;
                var selection = settings with { SelectedServerId = request.ServerId, Protocol = selectedMode };
                store.SaveSettings(selection); settings = selection;
                Log("Выбор сервера сохранён.");
                if (requestedOnline) QueueConnect();
                break;
            case "refresh":
                var provider = store.LoadProvider() ?? throw new InvalidOperationException("Не установлен ключ формата API. Выполните обновление клиента через Install.ps1.");
                var updated = await new PlanetCatalog(provider).RefreshAsync(Log, ct);
                SaveCatalog(ServerProfiles.Merge(servers, updated, settings.DeletedPlanetPools));
                Log($"Каталог PlanetVPN обновлён. Всего серверов: {servers.Length}.");
                break;
            case "import":
                var imported = ServerProfiles.Import(request.ImportJson ?? "", request.ImportFormat, request.ImportName,
                    request.ImportUser, request.ImportPassword);
                SaveCatalog(ServerProfiles.Merge(servers, imported, settings.DeletedPlanetPools));
                Log($"Импортировано профилей: {imported.Length}. Всего серверов: {servers.Length}.");
                break;
            case "delete-server":
                await DeleteServerAsync(request.ServerId);
                break;
            case "check-server":
                var checkedServer = servers.FirstOrDefault(server => server.Id == request.ServerId)
                    ?? throw new ArgumentException("Сервер не найден.");
                serverChecks[checkedServer.Id] = await PlanetCatalog.CheckAsync(checkedServer, ct);
                break;
            case "save":
                var next = Policy.Normalize(request.Settings ?? throw new ArgumentException("Нет настроек."));
                next = next with { LastSuccessfulServerId = settings.LastSuccessfulServerId, LastSuccessfulProtocol = settings.LastSuccessfulProtocol, DeletedPlanetPools = settings.DeletedPlanetPools };
                if (next.SelectedServerId is not (null or "recommended") && !servers.Any(s => s.Id == next.SelectedServerId)) throw new ArgumentException("Сервер не найден.");
                foreach (var rule in next.Rules.Where(r => r.Enabled && r.Kind == RuleKind.Application))
                {
                    if (!File.Exists(rule.Value)) throw new ArgumentException("Файл приложения не найден: " + rule.Value);
                    rule.Value = ApplicationPath.Canonicalize(rule.Value);
                    if (rule.Value.StartsWith(Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))! + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                        throw new ArgumentException("Компоненты самого VPN нельзя направлять в туннель.");
                }
                next = Policy.Normalize(next);
                var previous = settings;
                bool reconnect = requestedOnline && (next.SelectedServerId != previous.SelectedServerId || next.Protocol != previous.Protocol);
                guard.ReplaceProtectedApplications(previous.ProtectedApplications.Concat(next.ProtectedApplications));
                try
                {
                    await router.ApplyAsync(next, requestedOnline, ct);
                    store.SaveSettings(next);
                    settings = next;
                    guard.ReplaceProtectedApplications(settings.ProtectedApplications);
                    if (state == TunnelState.Connected) guard.OpenTunnel(Wire.InterfaceName);
                }
                catch
                {
                    await router.ApplyAsync(previous, requestedOnline, serviceToken);
                    store.SaveSettings(previous);
                    settings = previous;
                    guard.ReplaceProtectedApplications(previous.ProtectedApplications);
                    if (state == TunnelState.Connected) guard.OpenTunnel(Wire.InterfaceName);
                    throw;
                }
                disconnectedDomainFilter = state != TunnelState.Connected && settings.NeedsDisconnectedDomainFilter;
                if (reconnect) QueueConnect();
                Log("Правила сохранены без перезапуска сетевого движка.");
                break;
            case "connect": QueueConnect(); break;
            case "disconnect":
                requestedOnline = false;
                await StopVpnAsync();
                await ApplyRoutingAsync();
                SetState(TunnelState.Disconnected, "VPN отключён. Защищённые приложения заблокированы.");
                break;
            default: throw new ArgumentException("Неизвестная команда.");
        }
        return new(true, Status: Snapshot());
    }

    private void SaveCatalog(ServerProfile[] next, ClientSettings? updatedSettings = null)
    {
        var selection = updatedSettings ?? settings;
        if (selection.SelectedServerId != "recommended" && !next.Any(server => server.Id == selection.SelectedServerId))
            selection = selection with { SelectedServerId = "recommended", Protocol = VpnProtocol.Auto };

        store.SaveServers(next);
        var previous = servers.ToDictionary(server => server.Id, StringComparer.Ordinal);
        var changed = next.Where(server => !previous.TryGetValue(server.Id, out var old)
            || server.Address != old.Address || server.Port != old.Port || !server.Protocols.SequenceEqual(old.Protocols))
            .Select(server => server.Id).ToHashSet(StringComparer.Ordinal);
        servers = next;
        foreach (var key in serverChecks.Keys)
            if (changed.Contains(key) || !next.Any(server => server.Id == key)) serverChecks.TryRemove(key, out _);
        if (!ReferenceEquals(settings, selection))
        {
            store.SaveSettings(selection);
            settings = selection;
        }
    }

    private async Task DeleteServerAsync(string? id)
    {
        var removed = servers.FirstOrDefault(server => server.Id == id)
            ?? throw new ArgumentException("Сервер не найден.");
        var next = settings;
        if (removed.PoolId is int pool && !next.DeletedPlanetPools.Contains(pool))
            next = next with { DeletedPlanetPools = [.. next.DeletedPlanetPools, pool] };
        if (next.LastSuccessfulServerId == removed.Id)
            next = next with { LastSuccessfulServerId = null, LastSuccessfulProtocol = null };

        bool disconnect = activeServerId == removed.Id || (requestedOnline && servers.Length == 1);
        SaveCatalog(servers.Where(server => server.Id != removed.Id).ToArray(), next);
        if (disconnect)
        {
            requestedOnline = false;
            await StopVpnAsync();
            await ApplyRoutingAsync();
            SetState(TunnelState.Disconnected, "VPN отключён: активный сервер удалён.");
        }
        Log("Сервер удалён.");
    }

    private void QueueConnect()
    {
        connectionCancel?.Cancel(); connectionCancel?.Dispose();
        connectionCancel = CancellationTokenSource.CreateLinkedTokenSource(serviceToken);
        var token = connectionCancel.Token;
        if (successfulConnections > 0) reconnectAttempts++;
        requestedOnline = true;
        SetState(TunnelState.Connecting, "Подбор и проверка VPN. Прямые соединения сохраняются.");
        connectionTask = Task.Run(async () =>
        {
            await gate.WaitAsync(token);
            try { await ConnectAsync(token); }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                await StopVpnAsync();
                await ApplyRoutingAsync();
                SetState(TunnelState.Disconnected, "Подключение отменено.");
            }
            catch (Exception ex)
            {
                Failure(ex.Message);
                await StopVpnAsync();
                await ApplyRoutingAsync();
                retryAt = DateTime.UtcNow.AddSeconds(60);
                SetState(TunnelState.Faulted, ex.Message);
            }
            finally { gate.Release(); }
        }, CancellationToken.None);
    }

    private async Task ConnectAsync(CancellationToken ct)
    {
        await StopVpnAsync();
        HostNetwork.RejectConflictingVpn();
        var physical = await HostNetwork.GetPhysicalAsync(ct);
        var directIPv6Available = await CheckDirectIPv6Async(physical, ct);
        var candidates = settings.SelectedServerId is null or "recommended"
            ? await PlanetCatalog.RankAsync(servers, settings.LastSuccessfulServerId, ct)
            : servers.Where(s => s.Id == settings.SelectedServerId).ToArray();
        if (candidates.Length == 0) throw new InvalidOperationException("Список серверов пуст. Нажмите «Обновить серверы».");
        if (settings.Protocol != VpnProtocol.Auto && candidates.All(s => !s.Protocols.Contains(settings.Protocol))) throw new InvalidOperationException("Выбранный протокол отсутствует в конфигурации сервера. Выберите другой протокол или «Авто».");
        await router.EnsureAsync(settings, requestedOnline, physical.Name, directIPv6Available, ct);
        await router.ApplyAsync(settings, requestedOnline, ct);
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
                    if (protocol is not (VpnProtocol.VlessReality or VpnProtocol.WireGuard))
                    { await transport.StartAsync(server, protocol, physical, ct); vpnInterface = OpenVpnProcess.InterfaceName; }
                    await engine.StartAsync(settings with { DiagnosticLogging = true }, server, true, ct, tun: false, physicalInterface: physical.Name, vpnInterface: vpnInterface, directIPv6Available: directIPv6Available, protocol: protocol, fixedProbe: router.VpnEndpoint);
                    if (!await engine.ProbeAsync(ct)) throw new IOException("HTTPS через VPN недоступен.");
                    guard.OpenTunnel(Wire.InterfaceName); activeProtocol = protocol;
                    activeServerId = server.Id;
                    disconnectedDomainFilter = false;
                    consecutiveProbeFailures = 0;
                    connectedSince = DateTimeOffset.UtcNow;
                    connectedTimestamp = System.Diagnostics.Stopwatch.GetTimestamp();
                    if (successfulConnections > 0) lastReconnectedAt = connectedSince;
                    successfulConnections++;
                    settings = settings with { LastSuccessfulServerId = server.Id, LastSuccessfulProtocol = protocol };
                    store.SaveSettings(settings);
                    SetState(TunnelState.Connected, $"Подключено: {server.Name} · {protocol}"); return;
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                { Failure($"{server.Name} / {protocol}: {EngineProcess.SafeError(ex.Message, server)}"); await StopVpnAsync(); }
            }
        }
        throw new IOException("Серверы и протоколы не прошли проверку. Прямые соединения продолжают работать; VPN-трафик заблокирован. Причины — в журнале ниже.");
    }

    private async Task<bool> CheckDirectIPv6Async(PhysicalNetwork physical, CancellationToken ct)
    {
        bool available = await HostNetwork.CanReachPublicIPv6Async(physical, ct);
        Log(available ? "Прямой IPv6 доступен." : "Прямой IPv6 недоступен. Для прямых доменов используется IPv4.");
        return available;
    }

    private async Task ApplyRoutingAsync()
    {
        if (serviceToken.IsCancellationRequested) return;
        if (!router.Running)
        {
            HostNetwork.RejectConflictingVpn();
            var physical = await HostNetwork.GetPhysicalAsync(serviceToken);
            bool ipv6 = await CheckDirectIPv6Async(physical, serviceToken);
            await router.EnsureAsync(settings, requestedOnline, physical.Name, ipv6, serviceToken);
        }
        await router.ApplyAsync(settings, requestedOnline, serviceToken);
        disconnectedDomainFilter = state != TunnelState.Connected && settings.NeedsDisconnectedDomainFilter;
    }

    private Task StopVpnAsync()
    {
        disconnectedDomainFilter = false;
        consecutiveProbeFailures = 0;
        activeServerId = null;
        guard.CloseTunnel();
        if (connectedSince is not null) { totalConnectedSeconds += System.Diagnostics.Stopwatch.GetElapsedTime(connectedTimestamp).TotalSeconds; connectedSince = null; }
        try { engine.Stop(); }
        finally { transport.Stop(); }
        return Task.CompletedTask;
    }

    private async Task MonitorAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        while (await timer.WaitForNextTickAsync(ct))
        {
            if (!await gate.WaitAsync(0, ct)) continue;
            try
            {
                if (!router.Running)
                {
                    Log("Постоянный маршрутизатор завершился. Восстановление TUN после сбоя процесса.");
                    await ApplyRoutingAsync();
                    if (state == TunnelState.Connected) guard.OpenTunnel(Wire.InterfaceName);
                }
                string? failure = null;
                if (state == TunnelState.Connected)
                {
                    if (!engine.Running) failure = "Процесс сетевого движка завершился.";
                    else if (activeProtocol is not (VpnProtocol.VlessReality or VpnProtocol.WireGuard) && !transport.Running)
                        failure = "Процесс OpenVPN завершился.";
                    else if (await engine.ProbeAsync(ct))
                    {
                        if (consecutiveProbeFailures > 0) Log("Проверка VPN восстановилась без переподключения.");
                        consecutiveProbeFailures = 0;
                    }
                    else
                    {
                        consecutiveProbeFailures++;
                        Log($"Проверка VPN {consecutiveProbeFailures}/3, сервер {activeServerId}, {activeProtocol}: {engine.LastProbeFailure}");
                        if (consecutiveProbeFailures >= 3) failure = engine.LastProbeFailure;
                    }
                }
                if (failure is not null)
                {
                    Failure($"Сервер {activeServerId}, {activeProtocol}: {failure}");
                    await StopVpnAsync();
                    await ApplyRoutingAsync();
                    retryAt = DateTime.UtcNow.AddSeconds(30);
                    SetState(TunnelState.Faulted, "Соединение потеряно. Защищённые приложения заблокированы.");
                }
                else if (state == TunnelState.Faulted && requestedOnline && DateTime.UtcNow >= retryAt) QueueConnect();

            }
            finally { gate.Release(); }
        }
    }
    private async Task MonitorLogonsAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        while (await timer.WaitForNextTickAsync(ct))
        {
            HashSet<int> sessions;
            try { sessions = LogonSessions.Read(); } catch (Exception ex) { Log("Проверка входа в Windows: " + ex.Message); continue; }
            bool newLogon = sessions.Except(knownSessions).Any(); knownSessions = sessions;
            if (!newLogon) continue;
            await gate.WaitAsync(ct);
            try { if (settings.ConnectOnLogon && !requestedOnline) { Log("Автоподключение: вход пользователя в Windows"); QueueConnect(); } }
            finally { gate.Release(); }
        }
    }
    private StatusSnapshot Snapshot() => new(state, message, guard.Active, settings.ProtectedApplications.Length, Wire.Clone(settings),
        new[] { new ServerInfo("recommended", "Рекомендуемый — автоматический подбор", "", 0) }.Concat(servers.Select(s => new ServerInfo(s.Id, s.Name, s.Address, s.Port, s.Protocols, serverChecks.GetValueOrDefault(s.Id), s.Id == activeServerId))).ToArray(), events.ToArray(), new ConnectionStats(connectedSince, lastReconnectedAt, successfulConnections, reconnectAttempts, failures, lastFailureAt, lastFailure,
            state == TunnelState.Faulted && requestedOnline ? new DateTimeOffset(retryAt, TimeSpan.Zero) : null,
            totalConnectedSeconds + (connectedSince is null ? 0 : System.Diagnostics.Stopwatch.GetElapsedTime(connectedTimestamp).TotalSeconds)),
        DisconnectedDomainFilterActive: disconnectedDomainFilter);
    private void SetState(TunnelState value, string text) { state = value; message = text; Log(text); }
    private void Log(string text)
    {
        events.Enqueue($"{DateTime.Now:HH:mm:ss} {text}"); while (events.Count > 120) events.TryDequeue(out _);
        try { store.AppendLog("service.log", text); } catch (IOException) { }
    }
}
