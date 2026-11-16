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
    string path = args[importIndex + 1];
    var imported = ServerProfiles.Import(await File.ReadAllTextAsync(path), Path.GetExtension(path), Path.GetFileNameWithoutExtension(path));
    var settings = store.LoadSettings();
    var servers = ServerProfiles.Merge(store.LoadServers(), imported, settings.DeletedPlanetPools);
    store.SaveServers(servers);
    if (!servers.Any(s => s.Id == settings.SelectedServerId)) settings.SelectedServerId = servers[0].Id;
    store.SaveSettings(settings);
    Console.WriteLine($"Imported {imported.Length} profiles. Total: {servers.Length}.");
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
    var settings = store.LoadSettings();
    var merged = ServerProfiles.Merge(store.LoadServers(), profiles, settings.DeletedPlanetPools);
    store.SaveServers(merged);
    if (!merged.Any(s => s.Id == settings.SelectedServerId)) settings.SelectedServerId = "recommended";
    store.SaveSettings(settings);
    Console.WriteLine($"Catalog contains {merged.Length} locations.");
    return;
}
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = Wire.ServiceName);
builder.Services.AddHostedService<VpnWorker>();
await builder.Build().RunAsync();
