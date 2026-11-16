using System.Text.Json.Nodes;

namespace SelectiveVpn.Core;

public sealed record ProbeEndpoint(int Port, string Username, string Password);

public static class EngineConfig
{
    public static JsonObject Build(ClientSettings rawSettings, ServerProfile? server, bool online, ProbeEndpoint probe, bool tun = true, string? physicalInterface = null, string? vpnInterface = null, bool directIPv6Available = true,
        VpnProtocol protocol = VpnProtocol.VlessReality)
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
        if (!string.IsNullOrEmpty(physicalInterface)) outbounds[0]!["bind_interface"] = physicalInterface;
        if (!directIPv6Available)
            outbounds[0]!["domain_resolver"] = new JsonObject { ["server"] = "dns-direct", ["strategy"] = "ipv4_only" };
        bool usesWireGuard = online && protocol == VpnProtocol.WireGuard;
        JsonObject? wireGuard = usesWireGuard ? BuildWireGuard(server!, physicalInterface) : null;
        if (online && !usesWireGuard && !string.IsNullOrEmpty(vpnInterface)) outbounds.Add(new JsonObject
        {
            ["type"] = "direct", ["tag"] = "vpn", ["bind_interface"] = vpnInterface,
            ["domain_resolver"] = new JsonObject { ["server"] = "dns-vpn", ["strategy"] = "ipv4_only" }
        });
        else if (online && !usesWireGuard) outbounds.Add(new JsonObject
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
        if (online && !usesWireGuard && string.IsNullOrEmpty(vpnInterface) && !string.IsNullOrEmpty(physicalInterface)) outbounds[^1]!["bind_interface"] = physicalInterface;
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
        if (usesWireGuard)
            rules.Insert(0, new JsonObject { ["inbound"] = "vpn", ["action"] = "reject" });
        if (settings.ProtectedApplications.Length > 0 && (online || !settings.BlockVpnDomainsWhenDisconnected))
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
        if (online)
        {
            string? wgDns = usesWireGuard ? server!.WireGuard!.Dns : null;
            dnsServers.Add(wgDns is not null
                ? new JsonObject { ["type"] = "udp", ["tag"] = "dns-vpn", ["server"] = wgDns, ["detour"] = "vpn" }
                : new JsonObject { ["type"] = "https", ["tag"] = "dns-vpn", ["server"] = "1.1.1.1", ["path"] = "/dns-query", ["detour"] = "vpn" });
        }
        if (!string.IsNullOrEmpty(physicalInterface)) dnsServers[0]!["bind_interface"] = physicalInterface;
        var result = new JsonObject
        {
            ["log"] = new JsonObject { ["level"] = settings.DiagnosticLogging ? "debug" : "info", ["timestamp"] = true },
            ["experimental"] = new JsonObject { ["cache_file"] = new JsonObject { ["enabled"] = tun, ["path"] = "cache.db", ["store_fakeip"] = true } },
            ["dns"] = new JsonObject
            {
                ["servers"] = dnsServers,
                ["rules"] = BuildDnsRules(settings, directIPv6Available),
                ["final"] = online ? "dns-vpn" : "dns-direct"
            },
            ["inbounds"] = inbounds, ["outbounds"] = outbounds,
            ["route"] = new JsonObject
            {
                ["auto_detect_interface"] = true, ["find_process"] = true,
                ["default_domain_resolver"] = "dns-direct", ["rules"] = rules, ["final"] = "direct"
            }
        };
        if (wireGuard is not null) result["endpoints"] = new JsonArray(wireGuard);
        return result;
    }

    private static JsonObject BuildWireGuard(ServerProfile server, string? physicalInterface)
    {
        var profile = server.WireGuard ?? throw new ArgumentException("Отсутствует профиль WireGuard.");
        var peer = new JsonObject
        {
            ["address"] = server.Address, ["port"] = server.Port, ["public_key"] = profile.PublicKey,
            ["allowed_ips"] = Strings(profile.AllowedIps), ["persistent_keepalive_interval"] = profile.KeepaliveSeconds
        };
        if (profile.PresharedKey is not null) peer["pre_shared_key"] = profile.PresharedKey;
        var endpoint = new JsonObject
        {
            ["type"] = "wireguard", ["tag"] = "vpn", ["system"] = false,
            ["address"] = Strings(profile.Addresses), ["private_key"] = profile.PrivateKey, ["peers"] = new JsonArray(peer),
            ["domain_resolver"] = "dns-direct"
        };
        if (!string.IsNullOrEmpty(physicalInterface)) endpoint["bind_interface"] = physicalInterface;
        if (profile.Mtu is not null) endpoint["mtu"] = profile.Mtu.Value;
        return endpoint;
    }

    private static JsonArray Strings(IEnumerable<string> values) =>
        new(values.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());

    private static JsonArray BuildDnsRules(ClientSettings settings, bool directIPv6Available)
    {
        var rules = new JsonArray();
        var orderedRules = Policy.Ordered(settings).ToArray();

        // Chrome treats synthetic IPv6 addresses in fc00::/7 as local network resources.
        // With domain-only routing we can return real AAAA records for direct destinations.
        // App and IP rules can change the route after DNS, so keep their synthetic answers.
        if (orderedRules.All(rule => rule.Kind is RuleKind.Domain or RuleKind.DomainSuffix))
        {
            foreach (var rule in orderedRules)
            {
                var match = rule.Target == RouteTarget.Direct
                    ? DirectAAAA(directIPv6Available) : ResolveTunAddresses("fakeip", "AAAA");
                string field = rule.Kind == RuleKind.Domain ? "domain" : "domain_suffix";
                match[field] = new JsonArray(rule.Value);
                rules.Add(match);
            }
            if (settings.DefaultRoute == RouteTarget.Direct) rules.Add(DirectAAAA(directIPv6Available));
        }
        rules.Add(ResolveTunAddresses("fakeip", "A", "AAAA"));
        return rules;
    }

    private static JsonObject DirectAAAA(bool available) => available
        ? ResolveTunAddresses("dns-direct", "AAAA")
        : new JsonObject
        {
            ["inbound"] = "tun-in",
            ["query_type"] = new JsonArray("AAAA"),
            ["action"] = "predefined",
            ["rcode"] = "NOERROR"
        };

    private static JsonObject ResolveTunAddresses(string server, params string[] queryTypes) => new()
    {
        ["inbound"] = "tun-in",
        ["query_type"] = Strings(queryTypes),
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
