using System.Text.Json;
using System.Text.Json.Serialization;

namespace SelectiveVpn.Core;

public enum RuleKind { Application, Domain, DomainSuffix, IpCidr }
public enum RouteTarget { Direct, Vpn }
public enum TunnelState { Starting, Disconnected, Connecting, Connected, Faulted, Stopping }

public sealed record RoutingRule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public bool Enabled { get; set; } = true;
    public RuleKind Kind { get; set; } = RuleKind.DomainSuffix;
    public string Value { get; set; } = "";
    public RouteTarget Target { get; set; } = RouteTarget.Vpn;
}

public sealed record ClientSettings
{
    public int SchemaVersion { get; init; } = 1;
    public bool AutoConnect { get; set; }
    public string? SelectedServerId { get; set; }
    public RouteTarget DefaultRoute { get; set; } = RouteTarget.Direct;
    public List<RoutingRule> Rules { get; set; } = [];
    [JsonIgnore]
    public string[] ProtectedApplications => Rules.Where(r => r.Enabled && r.Kind == RuleKind.Application && r.Target == RouteTarget.Vpn)
        .Select(r => r.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}

public sealed record ServerProfile(string Id, string Name, string Address, int Port, string Uuid,
    string PublicKey, string ShortId, string ServerName, string Fingerprint, string Flow);
public sealed record ServerInfo(string Id, string Name, string Address, int Port)
{
    [JsonIgnore] public string DisplayName => $"{Name} — {Address}:{Port}";
}
public sealed record StatusSnapshot(TunnelState State, string Message, bool ProtectionActive,
    int ProtectedApplications, ClientSettings Settings, ServerInfo[] Servers, string[] Events);
public sealed record RpcRequest(string Command, ClientSettings? Settings = null, string? ImportJson = null, string? ServerId = null);
public sealed record RpcResponse(bool Success, string? Error = null, StatusSnapshot? Status = null);

public static class Wire
{
    public const string PipeName = "SelectiveVpn.Control.v1";
    public const string ServiceName = "SelectiveVpn";
    public const string InterfaceName = "SelectiveVpn-TUN";
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() },
        MaxDepth = 32
    };
    public static T Clone<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value, Json), Json)!;
}
