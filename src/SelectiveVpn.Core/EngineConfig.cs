using System.Text.Json.Nodes;

namespace SelectiveVpn.Core;

public sealed record ProbeEndpoint(int Port, string Username, string Password);

public static class EngineConfig
{
    public static JsonObject Build(ClientSettings rawSettings, ServerProfile? server, bool online, ProbeEndpoint probe, bool tun = true)
    {
        var settings = Policy.Normalize(rawSettings);
        if (online && server is null) throw new ArgumentException("Выберите сервер.");
        var inbounds = new JsonArray();
        if (tun) inbounds.Add(new JsonObject
        {
            ["type"] = "tun", ["tag"] = "tun-in", ["interface_name"] = Wire.InterfaceName,
            ["address"] = new JsonArray("172.30.251.1/30", "fdfe:dcba:9876::1/126"),
            ["auto_route"] = true, ["strict_route"] = true, ["stack"] = "mixed", ["mtu"] = 1400,
            ["dns_mode"] = "hijack"
        });
        inbounds.Add(new JsonObject
        {
            ["type"] = "mixed", ["tag"] = "probe-in", ["listen"] = "127.0.0.1", ["listen_port"] = probe.Port,
            ["users"] = new JsonArray(new JsonObject { ["username"] = probe.Username, ["password"] = probe.Password })
        });
        var outbounds = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct" });
        if (online) outbounds.Add(new JsonObject
        {
            ["type"] = "vless", ["tag"] = "vpn", ["server"] = server!.Address, ["server_port"] = server.Port,
            ["uuid"] = server.Uuid, ["flow"] = server.Flow,
            ["tls"] = new JsonObject
            {
                ["enabled"] = true, ["server_name"] = server.ServerName,
                ["utls"] = new JsonObject { ["enabled"] = true, ["fingerprint"] = server.Fingerprint },
                ["reality"] = new JsonObject { ["enabled"] = true, ["public_key"] = server.PublicKey, ["short_id"] = server.ShortId }
            }
        });
        var rules = new JsonArray
        {
            new JsonObject { ["action"] = "sniff", ["timeout"] = "300ms" },
            new JsonObject { ["protocol"] = "dns", ["action"] = "hijack-dns" },
            WithTarget(new JsonObject { ["inbound"] = "probe-in" }, RouteTarget.Vpn, online)
        };
        if (settings.ProtectedApplications.Length > 0)
            rules.Add(new JsonObject { ["process_path_regex"] = new JsonArray(".+"), ["invert"] = true, ["action"] = "reject" });
        foreach (var rule in Policy.Ordered(settings))
        {
            var field = rule.Kind switch { RuleKind.Application => "process_path_regex", RuleKind.Domain => "domain", RuleKind.DomainSuffix => "domain_suffix", _ => "ip_cidr" };
            var value = rule.Kind == RuleKind.Application ? Policy.ProcessRegex(rule.Value) : rule.Value;
            rules.Add(WithTarget(new JsonObject { [field] = new JsonArray(value) }, rule.Target, online));
        }
        // Resolve unmatched domains before IP rules, so CIDR policies also apply to DNS names.
        var firstIp = rules.Select((n, i) => (n, i)).FirstOrDefault(x => x.n?["ip_cidr"] is not null);
        if (firstIp.n is not null) rules.Insert(firstIp.i, new JsonObject { ["action"] = "resolve", ["server"] = online ? "dns-vpn" : "dns-direct" });
        rules.Add(WithTarget(new JsonObject(), settings.DefaultRoute, online));
        var dnsServers = new JsonArray
        {
            new JsonObject { ["type"] = "https", ["tag"] = "dns-direct", ["server"] = "1.1.1.1", ["path"] = "/dns-query" },
            new JsonObject { ["type"] = "fakeip", ["tag"] = "fakeip", ["inet4_range"] = "198.18.0.0/15", ["inet6_range"] = "fc00::/18" }
        };
        if (online) dnsServers.Add(new JsonObject { ["type"] = "https", ["tag"] = "dns-vpn", ["server"] = "1.1.1.1", ["path"] = "/dns-query", ["detour"] = "vpn" });
        return new JsonObject
        {
            ["log"] = new JsonObject { ["level"] = "warn", ["timestamp"] = true },
            ["experimental"] = new JsonObject { ["cache_file"] = new JsonObject { ["enabled"] = tun, ["path"] = "cache.db", ["store_fakeip"] = true } },
            ["dns"] = new JsonObject
            {
                ["servers"] = dnsServers,
                ["rules"] = new JsonArray(new JsonObject { ["inbound"] = "tun-in", ["query_type"] = new JsonArray("A", "AAAA"), ["action"] = "route", ["server"] = "fakeip" }),
                ["final"] = online ? "dns-vpn" : "dns-direct"
            },
            ["inbounds"] = inbounds, ["outbounds"] = outbounds,
            ["route"] = new JsonObject
            {
                ["auto_detect_interface"] = true, ["find_process"] = true,
                ["default_domain_resolver"] = "dns-direct", ["rules"] = rules, ["final"] = "direct"
            }
        };
    }

    private static JsonObject WithTarget(JsonObject rule, RouteTarget target, bool online)
    {
        rule["action"] = target == RouteTarget.Vpn && !online ? "reject" : "route";
        if (rule["action"]!.ToString() == "route") rule["outbound"] = target == RouteTarget.Vpn ? "vpn" : "direct";
        return rule;
    }
}
