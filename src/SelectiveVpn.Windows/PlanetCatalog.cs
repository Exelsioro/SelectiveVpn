using System.Net.Sockets;
using System.Diagnostics;
using SelectiveVpn.Core;

namespace SelectiveVpn.Windows;

public sealed class PlanetCatalog
{
    private static readonly (int Id, string Name, string Country)[] Pools =
        [(54, "Германия", "DE"), (68, "Нидерланды", "NL"), (56, "Франция", "FR"), (59, "Великобритания", "GB"), (53, "США — Нью-Йорк", "US"), (57, "США — Портленд", "US")];
    private readonly ProviderSettings provider;
    public PlanetCatalog(ProviderSettings provider) => this.provider = provider;
    public async Task<ServerProfile[]> RefreshAsync(Action<string> log, CancellationToken ct)
    {
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(15), MaxResponseContentBufferSize = 2_000_000 };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("SelectiveVpn/0.2");
        var profiles = new List<ServerProfile>();
        foreach (var pool in Pools)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string json = await client.GetStringAsync($"https://api.freeplanetvpn.com/lite/v1/connection/config?nodes_pool_id={pool.Id}", ct);
                profiles.Add(PlanetApiCodec.ParseNode(PlanetApiCodec.Decode(json, provider.ConnectionKeyBase64), pool.Id, pool.Name, pool.Country));
                log("Получена конфигурация: " + pool.Name);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested && ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or InvalidDataException)
            { log($"Каталог {pool.Name}: {ex.Message}"); }
        }
        if (profiles.Count == 0) throw new IOException("Не удалось обновить каталог PlanetVPN. Сохранённый список не изменён.");
        return profiles.ToArray();
    }
    public static async Task<ServerProfile[]> RankAsync(ServerProfile[] profiles, string? preferred, CancellationToken ct)
    {
        var measurements = await Task.WhenAll(profiles.Select(async profile =>
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(1800);
            var watch = Stopwatch.StartNew();
            try { using var socket = new TcpClient(); await socket.ConnectAsync(profile.Address, profile.Port, timeout.Token); return (profile, score: watch.ElapsedMilliseconds); }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException) { return (profile, score: long.MaxValue); }
        }));
        return measurements.OrderBy(p => p.score == long.MaxValue ? 1 : 0).ThenBy(p => p.profile.Id == preferred ? 0 : 1).ThenBy(p => p.score).Select(p => p.profile).ToArray();
    }
}
