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
var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = Wire.ServiceName);
builder.Services.AddHostedService<VpnWorker>();
await builder.Build().RunAsync();
