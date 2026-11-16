using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SelectiveVpn.Core;

public static class ServerProfiles
{
    private const int MaxServers = 500;

    public static ServerProfile[] Import(string text, string? format, string? name, string? user = null, string? password = null)
    {
        if (text.Length > 4_000_000) throw new ArgumentException("Файл профилей слишком большой.");
        text = text.TrimStart('\uFEFF');
        name = string.IsNullOrWhiteSpace(name) ? "Импортированный сервер" : name.Trim();
        if (name.Length > 180 || name.Any(char.IsControl)) throw new ArgumentException("Некорректное название профиля.");
        return format?.ToLowerInvariant() switch
        {
            null or ".json" => ImportJson(text, name),
            ".ovpn" => [ImportOpenVpn(text, name, user, password)],
            ".conf" => [ImportWireGuard(text, name)],
            _ => throw new ArgumentException("Поддерживаются Xray JSON, OpenVPN .ovpn и WireGuard .conf.")
        };
    }

    public static ServerProfile[] Merge(IEnumerable<ServerProfile> current, IEnumerable<ServerProfile> incoming,
        IEnumerable<int>? deletedPools = null)
    {
        var hidden = deletedPools?.ToHashSet() ?? [];
        var incomingProfiles = incoming.ToArray();
        var profiles = current.Concat(incomingProfiles)
            .Where(profile => profile.PoolId is not int pool || !hidden.Contains(pool))
            .DistinctBy(profile => profile.Id, StringComparer.Ordinal)
            .ToArray();

        // Replace matching profiles in place and preserve the order of existing entries.
        var updates = incomingProfiles.Where(profile => profile.PoolId is not int pool || !hidden.Contains(pool))
            .ToDictionary(profile => profile.Id, StringComparer.Ordinal);
        if (profiles.Length > MaxServers) throw new InvalidOperationException($"Можно хранить до {MaxServers} серверов.");
        return profiles.Select(profile => updates.GetValueOrDefault(profile.Id, profile)).ToArray();
    }

    public static bool NeedsOpenVpnCredentials(string text) =>
        Lines(text.TrimStart('\uFEFF')).Any(line => line.Equals("auth-user-pass", StringComparison.OrdinalIgnoreCase)) &&
        !text.Contains("<auth-user-pass>", StringComparison.Ordinal);

    private static ServerProfile[] ImportJson(string text, string name)
    {
        var profiles = PlanetProfileImporter.Import(text).ToArray();
        if (profiles.Length == 1 && profiles[0].Name == "Импортированный сервер")
        {
            var profile = profiles[0];
            profiles[0] = profile with { Name = name, Id = Id("xray", name, profile.Address, profile.Port) };
        }
        return profiles;
    }

    private static ServerProfile ImportOpenVpn(string text, string name, string? user, string? password)
    {
        if (text.Length > 100_000) throw new ArgumentException("Файл OpenVPN слишком большой.");
        var config = new List<string>();
        var remotes = new List<string[]>();
        VpnProtocol? defaultProtocol = null;
        string? inline = null;
        bool hasClient = false, hasTun = false, hasCertCheck = false, askForCredentials = false, hasInlineAuth = false;
        foreach (string raw in text.Replace("\r", "").Split('\n'))
        {
            string line = raw.Trim();
            if (inline is not null)
            {
                config.Add(line);
                if (line == inline) inline = null;
                continue;
            }
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
            if (line.StartsWith('<'))
            {
                config.Add(line);
                if (!line.StartsWith("</", StringComparison.Ordinal))
                    inline = "</" + line[1..];
                hasInlineAuth |= line == "<auth-user-pass>";
                continue;
            }

            string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            switch (parts[0].ToLowerInvariant())
            {
                case "client": hasClient = true; break;
                case "dev":
                    if (parts.Length != 2 || !parts[1].Equals("tun", StringComparison.OrdinalIgnoreCase))
                        throw new ArgumentException("Для OpenVPN требуется dev tun.");
                    hasTun = true;
                    break;
                case "proto":
                    if (parts.Length != 2 || defaultProtocol is not null)
                        throw new ArgumentException("Некорректная директива proto.");
                    defaultProtocol = ParseOpenVpnProtocol(parts[1]);
                    break;
                case "remote": remotes.Add(parts); break;
                case "auth-user-pass":
                    if (parts.Length != 1)
                        throw new ArgumentException("Уберите имя файла из auth-user-pass: логин и пароль вводятся при импорте.");
                    askForCredentials = true;
                    continue;
                case "remote-cert-tls":
                    if (parts.Length != 2 || parts[1] != "server")
                        throw new ArgumentException("OpenVPN требует remote-cert-tls server.");
                    hasCertCheck = true;
                    break;
                // SelectiveVpn manages routes and DNS using its own rules.
                case "redirect-gateway":
                case "redirect-private":
                case "block-outside-dns":
                case "dhcp-option":
                case "route":
                case "route-ipv6":
                case "route-metric":
                case "route-nopull":
                    continue;
            }
            config.Add(line);
        }

        if (remotes.Count == 0) throw new ArgumentException("OpenVPN: укажите remote с явным портом.");
        var endpoints = remotes.Select(remote =>
        {
            if (remote.Length is < 3 or > 4) throw new ArgumentException("OpenVPN: ожидается remote адрес порт [протокол].");
            string host = Host(remote[1]);
            if (IPAddress.TryParse(host, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6)
                throw new ArgumentException("OpenVPN: требуется сервер с IPv4. Для одного IPv6 включите WireGuard или выберите другой профиль.");
            return (Host: host, Port: Number(remote[2], 1, 65535, "порт OpenVPN"),
                Protocol: remote.Length == 4 ? ParseOpenVpnProtocol(remote[3]) : defaultProtocol ?? VpnProtocol.OpenVpnUdp);
        }).ToArray();
        var first = endpoints[0];
        if (endpoints.Any(endpoint => endpoint.Protocol != first.Protocol))
            throw new ArgumentException("Используйте отдельные OpenVPN-профили для TCP и UDP.");
        if (askForCredentials && !hasInlineAuth)
        {
            if (string.IsNullOrWhiteSpace(user) || string.IsNullOrEmpty(password))
                throw new ArgumentException("OpenVPN: укажите логин и пароль при импорте.");
            if (user.Length > 512 || password.Length > 512 || user.Any(char.IsControl) || password.Any(char.IsControl) ||
                user != user.Trim() || password != password.Trim() || user.StartsWith('<') || password.StartsWith('<'))
                throw new ArgumentException("OpenVPN: недопустимый логин или пароль.");
            config.AddRange(["<auth-user-pass>", user, password, "</auth-user-pass>"]);
        }
        if (!hasClient) config.Insert(0, "client");
        if (!hasTun) config.Insert(1, "dev tun");
        if (!hasCertCheck) config.Insert(1, "remote-cert-tls server");
        string sanitized = OpenVpnConfiguration.Validate(string.Join('\n', config));
        return NewProfile("ovpn-" + first.Protocol, name, first.Host, first.Port) with
        {
            OpenVpnConfigs = new() { [first.Protocol] = sanitized }
        };
    }

    private static VpnProtocol ParseOpenVpnProtocol(string value) => value.ToLowerInvariant() switch
    {
        "udp" or "udp4" => VpnProtocol.OpenVpnUdp,
        "tcp" or "tcp-client" or "tcp4" or "tcp4-client" => VpnProtocol.OpenVpnTcp,
        _ => throw new ArgumentException("OpenVPN: поддерживаются клиентские TCP и UDP по IPv4.")
    };

    private static ServerProfile ImportWireGuard(string text, string name)
    {
        if (text.Length > 100_000) throw new ArgumentException("Файл WireGuard слишком большой.");
        var iface = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var peer = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, string>? active = null;
        foreach (string original in Lines(text))
        {
            string line = original.Split('#', 2)[0].Trim();
            if (line.Length == 0) continue;
            if (line.Equals("[Interface]", StringComparison.OrdinalIgnoreCase) && active is null) { active = iface; continue; }
            if (line.Equals("[Peer]", StringComparison.OrdinalIgnoreCase) && active == iface) { active = peer; continue; }
            if (line[0] == '[') throw new ArgumentException("WireGuard: поддерживается один раздел Interface и один Peer.");
            int separator = line.IndexOf('=');
            if (active is null || separator <= 0) throw new ArgumentException("WireGuard: ожидается строка Имя = Значение.");
            string key = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();
            string[] allowed = active == iface ? ["Address", "PrivateKey", "DNS", "MTU", "ListenPort", "Table"] :
                ["Endpoint", "PublicKey", "PresharedKey", "AllowedIPs", "PersistentKeepalive"];
            if (!allowed.Contains(key, StringComparer.OrdinalIgnoreCase))
                throw new ArgumentException("WireGuard: неподдерживаемый параметр. Скрипты и системные хуки запрещены.");
            if (!active.TryAdd(key, value)) throw new ArgumentException($"WireGuard: повторяющийся параметр {key}.");
        }

        string Required(Dictionary<string, string> section, string key) =>
            section.TryGetValue(key, out var value) && value.Length > 0 ? value : throw new ArgumentException($"WireGuard: отсутствует {key}.");
        string endpoint = Required(peer, "Endpoint");
        int colon = endpoint.LastIndexOf(':');
        if (colon <= 0) throw new ArgumentException("WireGuard: укажите Endpoint с явным портом.");
        string host = Host(endpoint[..colon].TrimStart('[').TrimEnd(']'));
        int port = Number(endpoint[(colon + 1)..], 1, 65535, "порт WireGuard");
        string[] addresses = List(Required(iface, "Address")).Select(InterfacePrefix).ToArray();
        string[] allowedIps = List(Required(peer, "AllowedIPs")).Select(Policy.NormalizeCidr).ToArray();
        if (addresses.Length is < 1 or > 16 || allowedIps.Length is < 1 or > 256)
            throw new ArgumentException("WireGuard: неверное количество адресов или разрешённых сетей.");
        string privateKey = WireGuardKey(Required(iface, "PrivateKey"), "PrivateKey");
        string publicKey = WireGuardKey(Required(peer, "PublicKey"), "PublicKey");
        string? preshared = peer.TryGetValue("PresharedKey", out string? psk) ? WireGuardKey(psk, "PresharedKey") : null;
        int keepalive = peer.TryGetValue("PersistentKeepalive", out var seconds) ? Number(seconds, 0, 65535, "PersistentKeepalive") : 0;
        int? mtu = iface.TryGetValue("MTU", out var valueMtu) ? Number(valueMtu, 1280, 9000, "MTU") : null;
        string? dns = iface.TryGetValue("DNS", out var rawDns)
            ? List(rawDns).FirstOrDefault(address => IPAddress.TryParse(address, out _)) : null;
        return NewProfile("wg", name, host, port) with
        {
            WireGuard = new(addresses, privateKey, publicKey, preshared, allowedIps, keepalive, mtu, dns)
        };
    }

    private static IEnumerable<string> Lines(string text) => text.Replace("\r", "").Split('\n')
        .Select(line => line.Trim()).Where(line => line.Length > 0 && !line.StartsWith('#') && !line.StartsWith(';'));

    private static string[] List(string value) => value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

    private static string InterfacePrefix(string prefix)
    {
        var parts = prefix.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address))
            throw new ArgumentException("WireGuard: адрес интерфейса указывается с длиной префикса.");
        int max = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        return $"{address}/{Number(parts[1], 1, max, "префикс интерфейса")}";
    }

    private static string WireGuardKey(string value, string name)
    {
        byte[]? bytes = null;
        try
        {
            bytes = Convert.FromBase64String(value);
            if (bytes.Length == 32) return Convert.ToBase64String(bytes);
        }
        catch (FormatException) { }
        finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
        throw new ArgumentException($"WireGuard: {name} должен быть ключом Base64 длиной 32 байта.");
    }

    private static string Host(string host)
    {
        host = host.Trim();
        if (IPAddress.TryParse(host, out var address)) return address.ToString();
        return Policy.NormalizeDomain(host, false);
    }

    private static int Number(string value, int min, int max, string field) =>
        int.TryParse(value, out int number) && number >= min && number <= max
            ? number : throw new ArgumentException($"Некорректный {field}.");

    private static ServerProfile NewProfile(string type, string name, string host, int port) =>
        new(Id(type, name, host, port), name, host, port, "", "", "", "", "", "");

    private static string Id(string type, string name, string host, int port) =>
        "import-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{type}|{name}|{host}|{port}")).AsSpan(0, 16)).ToLowerInvariant();
}
