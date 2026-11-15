using SelectiveVpn.Core;
using SelectiveVpn.Service;
using SelectiveVpn.Windows;

if (args.Contains("--remove-protection", StringComparer.Ordinal))
{
    WfpGuard.RemoveProtection();
    Console.WriteLine("SelectiveVpn application blocks removed.");
    return;
}
int importIndex = Array.IndexOf(args, "--import-profiles");
if (importIndex >= 0)
{
    if (importIndex + 1 >= args.Length) throw new ArgumentException("Profile file is required.");
    var store = new SecureStore();
    var servers = PlanetProfileImporter.Import(await File.ReadAllTextAsync(args[importIndex + 1])).ToArray();
    store.SaveServers(servers);
    var settings = store.LoadSettings();
    if (!servers.Any(s => s.Id == settings.SelectedServerId)) settings.SelectedServerId = servers[0].Id;
    store.SaveSettings(settings);
    Console.WriteLine($"Imported {servers.Length} profiles.");
    return;
}

int providerIndex = Array.IndexOf(args, "--import-provider");
if (providerIndex >= 0)
{
    var store = new SecureStore();
    var provider = System.Text.Json.JsonSerializer.Deserialize<ProviderSettings>(await File.ReadAllTextAsync(args[providerIndex + 1]), Wire.Json)!;
    store.SaveProvider(provider);
    Console.WriteLine("Provider format settings imported.");
    return;
}
if (args.Contains("--refresh-catalog", StringComparer.Ordinal))
{
    var store = new SecureStore();
    var provider = store.LoadProvider() ?? throw new InvalidOperationException("Import provider settings first.");
    var profiles = await new PlanetCatalog(provider).RefreshAsync(Console.WriteLine, CancellationToken.None);
    var merged = profiles.Concat(store.LoadServers().Where(s => s.PoolId is not null && profiles.All(n => n.Id != s.Id))).ToArray();
    store.SaveServers(merged);
    var settings = store.LoadSettings();
    if (!merged.Any(s => s.Id == settings.SelectedServerId)) settings.SelectedServerId = "recommended";
    store.SaveSettings(settings);
    Console.WriteLine($"Catalog contains {merged.Length} locations.");
    return;
}
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = Wire.ServiceName);
builder.Services.AddHostedService<VpnWorker>();
await builder.Build().RunAsync();
