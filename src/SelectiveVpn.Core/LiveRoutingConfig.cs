using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SelectiveVpn.Core;

// One ordered decision tree preserves application > domain > IP and first-match order.
public static class LiveRoutingPolicy
{
    public static readonly JsonSerializerOptions Json = new() { MaxDepth = 8192 };
    public static readonly string[] Tags = ["policy", "resolve-vpn", "synthetic-aaaa"];

    public static ClientSettings Effective(ClientSettings settings, bool requestedOnline) =>
        requestedOnline || settings.NeedsDisconnectedDomainFilter
            ? settings with { DefaultRoute = requestedOnline ? settings.DefaultRoute : RouteTarget.Direct }
            : settings with { DefaultRoute = RouteTarget.Direct, Rules = settings.Rules.Where(r => r.Kind == RuleKind.Application).ToList() };

    public static JsonObject Build(ClientSettings raw, bool requestedOnline, string tag, string revision)
    {
        var settings = Effective(Policy.Normalize(raw), requestedOnline);
        var rules = Policy.Ordered(settings).ToArray();
        bool hasIp = rules.Any(r => r.Kind == RuleKind.IpCidr);
        bool allSynthetic = tag == "synthetic-aaaa" && rules.Any(r => r.Kind is RuleKind.Application or RuleKind.IpCidr);
        var applicable = rules.Where(rule => tag switch
        {
            "resolve-vpn" => rule.Kind != RuleKind.IpCidr,
            "synthetic-aaaa" => rule.Kind is RuleKind.Domain or RuleKind.DomainSuffix,
            _ => true
        }).ToArray();
        var (any, vpn) = Compile(applicable, 0, applicable.Length);
        bool vpnDefault = settings.DefaultRoute == RouteTarget.Vpn && !(tag == "resolve-vpn" && hasIp);
        JsonObject decision = allSynthetic ? Constant(true) : vpnDefault ? Logical("or", vpn, Not(any)) : vpn;
        if (requestedOnline && settings.ProtectedApplications.Length > 0 && tag != "synthetic-aaaa")
            decision = Logical("or", new JsonObject { ["process_path_regex"] = new JsonArray(".+"), ["invert"] = true }, decision);
        decision = Logical("and", new JsonObject { ["domain_suffix"] = "selectivevpn.invalid", ["invert"] = true }, decision);
        return new JsonObject
        {
            ["version"] = 3,
            ["rules"] = new JsonArray(decision, new JsonObject { ["domain"] = new JsonArray(RevisionHost(tag, revision)) })
        };
    }

    public static string RevisionHost(string tag, string revision) => $"{revision}.{tag}.selectivevpn.invalid";

    public static RouteTarget Evaluate(ClientSettings raw, bool requestedOnline, string process, string host, string address)
    {
        var settings = Effective(raw, requestedOnline);
        if (requestedOnline && settings.ProtectedApplications.Length > 0 && process.Length == 0) return RouteTarget.Vpn;
        foreach (var rule in Policy.Ordered(settings))
        {
            bool matches = rule.Kind switch
            {
                RuleKind.Application => string.Equals(process, rule.Value, StringComparison.OrdinalIgnoreCase),
                RuleKind.Domain => string.Equals(host.TrimEnd('.'), rule.Value, StringComparison.OrdinalIgnoreCase),
                RuleKind.DomainSuffix => string.Equals(host.TrimEnd('.'), rule.Value, StringComparison.OrdinalIgnoreCase)
                    || host.TrimEnd('.').EndsWith("." + rule.Value, StringComparison.OrdinalIgnoreCase),
                RuleKind.IpCidr => IPAddress.TryParse(address, out var ip) && IPNetwork.Parse(rule.Value).Contains(ip),
                _ => false
            };
            if (matches) return rule.Target;
        }
        return settings.DefaultRoute;
    }

    // A balanced tree keeps the supported 1000-rule policy within parser depth limits.
    private static (JsonObject Any, JsonObject Vpn) Compile(RoutingRule[] rules, int start, int count)
    {
        if (count == 0) return (Constant(false), Constant(false));
        if (count == 1)
        {
            var match = Match(rules[start]);
            return (match, rules[start].Target == RouteTarget.Vpn ? match.DeepClone().AsObject() : Constant(false));
        }
        int middle = count / 2;
        var left = Compile(rules, start, middle);
        var right = Compile(rules, start + middle, count - middle);
        var vpn = Logical("or", left.Vpn, Logical("and", Not(left.Any.DeepClone().AsObject()), right.Vpn));
        return (Logical("or", left.Any, right.Any), vpn);
    }

    private static JsonObject Not(JsonObject rule)
    {
        rule["invert"] = !(rule["invert"]?.GetValue<bool>() ?? false);
        return rule;
    }

    private static JsonObject Match(RoutingRule rule)
    {
        string field = rule.Kind switch
        {
            RuleKind.Application => "process_path_regex", RuleKind.Domain => "domain",
            RuleKind.DomainSuffix => "domain_suffix", _ => "ip_cidr"
        };
        return new JsonObject { [field] = new JsonArray(rule.Kind == RuleKind.Application ? Policy.ProcessRegex(rule.Value) : rule.Value) };
    }

    private static JsonObject Constant(bool value) => new()
    {
        ["type"] = "logical", ["mode"] = "and", ["invert"] = value,
        ["rules"] = new JsonArray(new JsonObject { ["network"] = "tcp" }, new JsonObject { ["network"] = "udp" })
    };

    private static JsonObject Logical(string mode, JsonObject first, JsonObject rest) => new()
    {
        ["type"] = "logical", ["mode"] = mode, ["rules"] = new JsonArray(first, rest)
    };
}

public static class LiveRoutingConfig
{
    public static JsonObject Build(ClientSettings settings, ProbeEndpoint inbound, ProbeEndpoint vpn,
        int acknowledgementPort, int controlPort, string secret, string? physicalInterface, bool directIPv6Available, bool tun = true)
    {
        var config = EngineConfig.Build(settings, null, false, inbound, tun, physicalInterface: physicalInterface, directIPv6Available: directIPv6Available);
        // The service filters debug records live so changing verbosity never restarts this process.
        config["log"]!["level"] = "debug";
        var outbounds = config["outbounds"]!.AsArray();
        outbounds.Add(new JsonObject { ["type"] = "direct", ["tag"] = "control" });
        outbounds.Add(new JsonObject
        {
            ["type"] = "socks", ["tag"] = "vpn", ["server"] = "127.0.0.1", ["server_port"] = vpn.Port,
            ["version"] = "5", ["username"] = vpn.Username, ["password"] = vpn.Password
        });
        config["experimental"]!["clash_api"] = new JsonObject { ["external_controller"] = $"127.0.0.1:{controlPort}", ["secret"] = secret };
        config["dns"]!["servers"]!.AsArray().Add(new JsonObject
        {
            ["type"] = "https", ["tag"] = "dns-vpn", ["server"] = "1.1.1.1", ["path"] = "/dns-query", ["detour"] = "vpn"
        });
        config["dns"]!["final"] = "dns-direct";
        var dnsRules = new JsonArray
        {
            new JsonObject { ["inbound"] = "tun-in", ["query_type"] = "AAAA", ["rule_set"] = "synthetic-aaaa", ["action"] = "route", ["server"] = "fakeip" }
        };
        dnsRules.Add(directIPv6Available
            ? new JsonObject { ["inbound"] = "tun-in", ["query_type"] = "AAAA", ["action"] = "route", ["server"] = "dns-direct" }
            : new JsonObject { ["inbound"] = "tun-in", ["query_type"] = "AAAA", ["action"] = "predefined", ["rcode"] = "NOERROR" });
        dnsRules.Add(new JsonObject { ["inbound"] = "tun-in", ["query_type"] = "A", ["action"] = "route", ["server"] = "fakeip" });
        config["dns"]!["rules"] = dnsRules;

        var routes = new JsonArray
        {
            new JsonObject { ["action"] = "sniff", ["timeout"] = "300ms" },
            new JsonObject { ["protocol"] = "dns", ["action"] = "hijack-dns" }
        };
        foreach (var tag in LiveRoutingPolicy.Tags)
            routes.Add(new JsonObject
            {
                ["domain_suffix"] = tag + ".selectivevpn.invalid", ["rule_set"] = tag, ["action"] = "route",
                ["outbound"] = "control", ["override_address"] = "127.0.0.1", ["override_port"] = acknowledgementPort
            });
        routes.Add(new JsonObject { ["domain_suffix"] = "selectivevpn.invalid", ["action"] = "reject" });
        routes.Add(new JsonObject
        {
            ["domain_regex"] = new JsonArray(".+"), ["rule_set"] = "resolve-vpn", ["action"] = "resolve",
            ["server"] = "dns-vpn", ["strategy"] = "prefer_ipv4"
        });
        routes.Add(new JsonObject
        {
            ["type"] = "logical", ["mode"] = "and", ["rules"] = new JsonArray(
                new JsonObject { ["domain_regex"] = new JsonArray(".+") }, new JsonObject { ["rule_set"] = "resolve-vpn", ["invert"] = true }), ["action"] = "resolve",
            ["server"] = "dns-direct", ["strategy"] = directIPv6Available ? "prefer_ipv4" : "ipv4_only"
        });
        routes.Add(new JsonObject { ["rule_set"] = "policy", ["action"] = "route", ["outbound"] = "vpn" });
        routes.Add(new JsonObject { ["action"] = "route", ["outbound"] = "direct" });
        config["route"]!["rules"] = routes;
        var sets = new JsonArray();
        foreach (var tag in LiveRoutingPolicy.Tags)
            sets.Add(new JsonObject { ["type"] = "local", ["tag"] = tag, ["format"] = "source", ["path"] = tag + ".json" });
        config["route"]!["rule_set"] = sets;
        return config;
    }
}
