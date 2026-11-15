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
    private TunnelState state = TunnelState.Starting;
    private string message = "Запуск службы";
    private bool requestedOnline;
    private DateTime retryAt;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // A corrupted store must never clear the already installed persistent block filters.
        store = new SecureStore();
        settings = store.LoadSettings();
        servers = store.LoadServers();
        using var localGuard = guard = new WfpGuard();
        using var localEngine = engine = new EngineProcess(Path.Combine(AppContext.BaseDirectory, "runtime", "sing-box.exe"), store, Log);
        guard.ReplaceProtectedApplications(settings.ProtectedApplications);
        requestedOnline = settings.AutoConnect;
        await gate.WaitAsync(stoppingToken);
        try { await RestartAsync(stoppingToken); }
        finally { gate.Release(); }
        try { await Task.WhenAll(ListenAsync(stoppingToken), MonitorAsync(stoppingToken)); }
        finally
        {
            state = TunnelState.Stopping;
            guard.CloseTunnel();
            engine.Stop();
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
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(60));
                var request = await PipeRpc.ReadAsync<RpcRequest>(pipe, deadline.Token);
                await gate.WaitAsync(deadline.Token);
                RpcResponse response;
                try { response = await HandleAsync(request, deadline.Token); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                { response = new(false, ex.Message, Snapshot()); }
                finally { gate.Release(); }
                await PipeRpc.WriteAsync(pipe, response, deadline.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { Log("Истёк срок запроса управления."); }
            catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or InvalidDataException)
            { Log("Отклонён незавершённый или некорректный запрос управления."); }
        }
    }

    private async Task<RpcResponse> HandleAsync(RpcRequest request, CancellationToken ct)
    {
        switch (request.Command)
        {
            case "status": break;
            case "select-server":
                if (string.IsNullOrWhiteSpace(request.ServerId) || !servers.Any(s => s.Id == request.ServerId))
                    throw new ArgumentException("Сервер не найден в импортированном списке.");
                var selection = settings with { SelectedServerId = request.ServerId };
                store.SaveSettings(selection);
                settings = selection;
                Log("Выбранный сервер сохранён.");
                if (requestedOnline) await RestartAsync(ct);
                break;
            case "import":
                var imported = PlanetProfileImporter.Import(request.ImportJson ?? "").ToArray();
                store.SaveServers(imported);
                servers = imported;
                if (!servers.Any(s => s.Id == settings.SelectedServerId)) settings.SelectedServerId = servers[0].Id;
                store.SaveSettings(settings);
                Log($"Импортировано серверов: {servers.Length}");
                await RestartAsync(ct);
                break;
            case "save":
                var next = Policy.Normalize(request.Settings ?? throw new ArgumentException("Нет настроек."));
                if (next.SelectedServerId is not null && !servers.Any(s => s.Id == next.SelectedServerId)) throw new ArgumentException("Сервер не найден.");
                foreach (var rule in next.Rules.Where(r => r.Enabled && r.Kind == RuleKind.Application))
                {
                    var path = rule.Value;
                    if (!File.Exists(path)) throw new ArgumentException($"Файл приложения не найден: {path}");
                    path = rule.Value = ApplicationPath.Canonicalize(path);
                    if (path.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase) ||
                        path.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
                        throw new ArgumentException("Нельзя направлять собственные компоненты VPN обратно в туннель.");
                }
                next = Policy.Normalize(next);
                // Install the stricter union first. A failed write leaves existing AND new apps blocked.
                guard.ReplaceProtectedApplications(settings.ProtectedApplications.Concat(next.ProtectedApplications));
                store.SaveSettings(next);
                settings = next;
                guard.ReplaceProtectedApplications(settings.ProtectedApplications);
                Log("Правила сохранены; соединения пересоздаются.");
                await RestartAsync(ct);
                break;
            case "connect": requestedOnline = true; await RestartAsync(ct); break;
            case "disconnect": requestedOnline = false; await RestartAsync(ct); break;
            default: throw new ArgumentException("Неизвестная команда.");
        }
        return new(true, Status: Snapshot());
    }

    private async Task RestartAsync(CancellationToken ct)
    {
        guard.CloseTunnel();
        engine.Stop();
        SetState(requestedOnline ? TunnelState.Connecting : TunnelState.Disconnected, requestedOnline ? "Проверка VPN-соединения" : "VPN отключён; выбранные приложения заблокированы");
        try
        {
            var server = servers.FirstOrDefault(s => s.Id == settings.SelectedServerId);
            await engine.StartAsync(settings, server, requestedOnline, ct);
            if (requestedOnline)
            {
                bool healthy = false;
                for (int i = 0; i < 3 && !healthy; i++) { healthy = await engine.ProbeAsync(ct); if (!healthy) await Task.Delay(500, ct); }
                if (!healthy) throw new IOException("VPN-сервер не прошёл проверку HTTPS. Доступ защищённых приложений закрыт.");
                guard.OpenTunnel(Wire.InterfaceName);
                SetState(TunnelState.Connected, "VPN подключён; правила действуют");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            guard.CloseTunnel(); engine.Stop();
            SetState(TunnelState.Faulted, ex.Message);
            retryAt = DateTime.UtcNow.AddSeconds(30);
            // Keep routing/domain reject policy active even when the remote endpoint is unavailable.
            try { await engine.StartAsync(settings, null, false, ct); }
            catch (Exception fallback) when (fallback is not OperationCanceledException) { Log("Локальная маршрутизация недоступна: " + fallback.Message); }
        }
        catch { guard.CloseTunnel(); engine.Stop(); SetState(TunnelState.Faulted, "Операция прервана; защищённые приложения заблокированы"); throw; }
    }

    private async Task MonitorAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        var nextHealth = DateTime.UtcNow.AddSeconds(15);
        while (await timer.WaitForNextTickAsync(ct))
        {
            await gate.WaitAsync(ct);
            try
            {
                if (!engine.Running || (state == TunnelState.Connected && DateTime.UtcNow >= nextHealth && !await engine.ProbeAsync(ct)))
                {
                    guard.CloseTunnel();
                    SetState(TunnelState.Faulted, "Потеря соединения; защищённые приложения заблокированы");
                    await RestartAsync(ct);
                }
                else if (state == TunnelState.Faulted && requestedOnline && DateTime.UtcNow >= retryAt) await RestartAsync(ct);
                if (DateTime.UtcNow >= nextHealth) nextHealth = DateTime.UtcNow.AddSeconds(15);
            }
            finally { gate.Release(); }
        }
    }

    private StatusSnapshot Snapshot() => new(state, message, guard.Active, settings.ProtectedApplications.Length,
        Wire.Clone(settings), servers.Select(s => new ServerInfo(s.Id, s.Name, s.Address, s.Port)).ToArray(), events.ToArray());
    private void SetState(TunnelState value, string text) { state = value; message = text; Log(text); }
    private void Log(string text)
    {
        if (events.TryPeek(out var previous) && previous.EndsWith(text, StringComparison.Ordinal)) return;
        events.Enqueue($"{DateTime.Now:HH:mm:ss} {text}");
        while (events.Count > 80) events.TryDequeue(out _);
    }
}
