using System.Text.Json;
using System.Text.Json.Serialization;

namespace SelectiveVpn.Core;

public enum RuleKind { Application, Domain, DomainSuffix, IpCidr }
public enum RouteTarget { Direct, Vpn }
public enum TunnelState { Starting, Disconnected, Connecting, Connected, Faulted, Stopping }
public enum VpnProtocol { Auto, VlessReality, OpenVpnUdp, OpenVpnTcp, OpenVpnXorUdp, OpenVpnXorTcp }

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
    public bool ConnectOnLogon { get; set; }
    public bool DiagnosticLogging { get; set; }
    public bool BlockVpnDomainsWhenDisconnected { get; set; }
    public string? SelectedServerId { get; set; }
    public VpnProtocol Protocol { get; set; } = VpnProtocol.Auto;
    public string? LastSuccessfulServerId { get; set; }
    public VpnProtocol? LastSuccessfulProtocol { get; set; }
    public RouteTarget DefaultRoute { get; set; } = RouteTarget.Direct;
    public List<RoutingRule> Rules { get; set; } = [];
    [JsonIgnore]
    public bool NeedsDisconnectedDomainFilter => BlockVpnDomainsWhenDisconnected && Rules.Any(
        rule => rule.Enabled && rule.Target == RouteTarget.Vpn &&
            rule.Kind is RuleKind.Domain or RuleKind.DomainSuffix);

    [JsonIgnore]
    public string[] ProtectedApplications => Rules.Where(r => r.Enabled && r.Kind == RuleKind.Application && r.Target == RouteTarget.Vpn)
        .Select(r => r.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}

public sealed record ServerProfile(string Id, string Name, string Address, int Port, string Uuid,
    string PublicKey, string ShortId, string ServerName, string Fingerprint, string Flow)
{
    public int? PoolId { get; init; }
    public string? Country { get; init; }
    public Dictionary<VpnProtocol, string> OpenVpnConfigs { get; init; } = [];
    public string AccessUser { get; init; } = "";
    public string AccessKey { get; init; } = "";
    [JsonIgnore] public VpnProtocol[] Protocols => (Uuid.Length > 0 ? new[] { VpnProtocol.VlessReality } : []).Concat(OpenVpnConfigs.Keys).ToArray();
}
public sealed record ServerInfo(string Id, string Name, string Address, int Port, VpnProtocol[]? Protocols = null)
{
    [JsonIgnore] public string DisplayName => Address.Length == 0 ? Name : $"{Name} — {Address}:{Port}";
}
public sealed record StatusSnapshot(TunnelState State, string Message, bool ProtectionActive,
    int ProtectedApplications, ClientSettings Settings, ServerInfo[] Servers, string[] Events, ConnectionStats? Connection = null, bool DisconnectedDomainFilterActive = false);
public sealed record ConnectionStats(DateTimeOffset? ConnectedSince, DateTimeOffset? LastReconnectedAt, int SuccessfulConnections, int ReconnectAttempts, int Failures, DateTimeOffset? LastFailureAt, string? LastFailure, DateTimeOffset? NextRetryAt, double TotalConnectedSeconds);
public sealed record RpcRequest(string Command, ClientSettings? Settings = null, string? ImportJson = null, string? ServerId = null, VpnProtocol? Protocol = null);
public sealed record ProviderSettings(string ConnectionKeyBase64);
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
