using System.Text.Json.Nodes;

namespace SelectiveVpn.Core;

public sealed record ProbeEndpoint(int Port, string Username, string Password);

public static class EngineConfig
{
    public static JsonObject Build(ClientSettings rawSettings, ServerProfile? server, bool online, ProbeEndpoint probe, bool tun = true, string? physicalInterface = null, string? vpnInterface = null)
    {
        var settings = Policy.Normalize(rawSettings);
        if (online && server is null) throw new ArgumentException("Выберите сервер.");
        var inbounds = new JsonArray();
        if (tun) inbounds.Add(new JsonObject
        {
            ["type"] = "tun", ["tag"] = "tun-in", ["interface_name"] = Wire.InterfaceName,
            ["address"] = new JsonArray("172.30.251.1/30", "fdfe:dcba:9876::1/126"),
            ["auto_route"] = true, ["strict_route"] = false, ["stack"] = "mixed", ["mtu"] = 1400,
            ["dns_mode"] = "native"
        });
        inbounds.Add(new JsonObject
        {
            ["type"] = "mixed", ["tag"] = "probe-in", ["listen"] = "127.0.0.1", ["listen_port"] = probe.Port,
            ["users"] = new JsonArray(new JsonObject { ["username"] = probe.Username, ["password"] = probe.Password })
        });
        var outbounds = new JsonArray(new JsonObject { ["type"] = "direct", ["tag"] = "direct" });
        if (physicalInterface is not null) outbounds[0]!["bind_interface"] = physicalInterface;
        if (online && vpnInterface is not null) outbounds.Add(new JsonObject
        {
            ["type"] = "direct", ["tag"] = "vpn", ["bind_interface"] = vpnInterface,
            ["domain_resolver"] = new JsonObject { ["server"] = "dns-vpn", ["strategy"] = "ipv4_only" }
        });
        else if (online) outbounds.Add(new JsonObject
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
        if (online && vpnInterface is null && physicalInterface is not null) outbounds[^1]!["bind_interface"] = physicalInterface;
        if (tun && server is not null)
        {
            var exclusions = new JsonArray();
            var addresses = new List<string> { server.Address };
            foreach (var config in server.OpenVpnConfigs.Values)
                foreach (var line in config.Split('\n').Where(l => l.StartsWith("remote ")))
                    addresses.Add(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1]);
            foreach (string address in addresses.Distinct())
                if (System.Net.IPAddress.TryParse(address, out var ip)) exclusions.Add(address + (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "/32" : "/128"));
            inbounds[0]!["route_exclude_address"] = exclusions;
        }
        var rules = new JsonArray
        {
            new JsonObject { ["action"] = "sniff", ["timeout"] = "300ms" },
            new JsonObject { ["protocol"] = "dns", ["action"] = "hijack-dns" },
            WithTarget(new JsonObject { ["inbound"] = "probe-in" }, RouteTarget.Vpn, online)
        };
        if (settings.ProtectedApplications.Length > 0)
            rules.Add(WithTarget(new JsonObject { ["process_path_regex"] = new JsonArray(".+"), ["invert"] = true }, RouteTarget.Vpn, online));
        foreach (var rule in Policy.Ordered(settings))
        {
            var field = rule.Kind switch { RuleKind.Application => "process_path_regex", RuleKind.Domain => "domain", RuleKind.DomainSuffix => "domain_suffix", _ => "ip_cidr" };
            var value = rule.Kind == RuleKind.Application ? Policy.ProcessRegex(rule.Value) : rule.Value;
            rules.Add(WithTarget(new JsonObject { [field] = new JsonArray(value) }, rule.Target, online));
        }
        // Resolve unmatched domains before IP rules, so CIDR policies also apply to DNS names.
        var firstIp = rules.Select((n, i) => (n, i)).FirstOrDefault(x => x.n?["ip_cidr"] is not null);
        if (firstIp.n is not null) rules.Insert(firstIp.i, new JsonObject { ["domain_regex"] = new JsonArray(".+"), ["action"] = "resolve", ["server"] = online ? "dns-vpn" : "dns-direct" });
        rules.Add(WithTarget(new JsonObject(), settings.DefaultRoute, online));
        var dnsServers = new JsonArray
        {
            new JsonObject { ["type"] = "https", ["tag"] = "dns-direct", ["server"] = "1.1.1.1", ["path"] = "/dns-query" },
            new JsonObject { ["type"] = "fakeip", ["tag"] = "fakeip", ["inet4_range"] = "198.18.0.0/15", ["inet6_range"] = "fc00::/18" }
        };
        if (online) dnsServers.Add(new JsonObject { ["type"] = "https", ["tag"] = "dns-vpn", ["server"] = "1.1.1.1", ["path"] = "/dns-query", ["detour"] = "vpn" });
        if (physicalInterface is not null) dnsServers[0]!["bind_interface"] = physicalInterface;
        return new JsonObject
        {
            ["log"] = new JsonObject { ["level"] = settings.DiagnosticLogging ? "debug" : "info", ["timestamp"] = true },
            ["experimental"] = new JsonObject { ["cache_file"] = new JsonObject { ["enabled"] = tun, ["path"] = "cache.db", ["store_fakeip"] = true } },
            ["dns"] = new JsonObject
            {
                ["servers"] = dnsServers,
                ["rules"] = BuildDnsRules(settings),
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


    private static JsonArray BuildDnsRules(ClientSettings settings)
    {
        var rules = new JsonArray();
        var orderedRules = Policy.Ordered(settings).ToArray();

        // Chrome treats synthetic IPv6 addresses in fc00::/7 as local network resources.
        // With domain-only routing we can return real AAAA records for direct destinations.
        // App and IP rules can change the route after DNS, so keep their synthetic answers.
        if (settings.DefaultRoute == RouteTarget.Direct &&
            orderedRules.All(rule => rule.Kind is RuleKind.Domain or RuleKind.DomainSuffix))
        {
            foreach (var rule in orderedRules)
            {
                var match = ResolveTunAddresses(rule.Target == RouteTarget.Direct ? "dns-direct" : "fakeip", "AAAA");
                string field = rule.Kind == RuleKind.Domain ? "domain" : "domain_suffix";
                match[field] = new JsonArray(rule.Value);
                rules.Add(match);
            }
            rules.Add(ResolveTunAddresses("dns-direct", "AAAA"));
        }
        rules.Add(ResolveTunAddresses("fakeip", "A", "AAAA"));
        return rules;
    }

    private static JsonObject ResolveTunAddresses(string server, params string[] queryTypes) => new()
    {
        ["inbound"] = "tun-in",
        ["query_type"] = new JsonArray(queryTypes.Select(type => (JsonNode?)JsonValue.Create(type)).ToArray()),
        ["action"] = "route",
        ["server"] = server
    };

    private static JsonObject WithTarget(JsonObject rule, RouteTarget target, bool online)
    {
        rule["action"] = target == RouteTarget.Vpn && !online ? "reject" : "route";
        if (rule["action"]!.ToString() == "route") rule["outbound"] = target == RouteTarget.Vpn ? "vpn" : "direct";
        return rule;
    }
}
