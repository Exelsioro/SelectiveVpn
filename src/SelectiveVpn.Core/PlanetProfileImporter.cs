using System.Text.Json.Nodes;

namespace SelectiveVpn.Core;

public static class PlanetProfileImporter
{
    public static List<ServerProfile> Import(string json)
    {
        if (json.Length > 4_000_000) throw new ArgumentException("Файл профилей слишком большой.");
        var root = JsonNode.Parse(json) ?? throw new ArgumentException("Пустой JSON.");
        var profiles = new List<ServerProfile>();
        if (root["data"] is JsonArray nodes)
        {
            foreach (var node in nodes)
            {
                if (node?["xray_config"] is not JsonValue value || !value.TryGetValue<string>(out var config) || string.IsNullOrWhiteSpace(config)) continue;
                var id = node["node_id"]?.ToString() ?? Guid.NewGuid().ToString("N");
                var name = $"{node["city"]?.ToString().Trim() ?? "PlanetVPN"} · {id}";
                profiles.Add(ParseXray(JsonNode.Parse(config)!, id, name));
            }
        }
        else profiles.Add(ParseXray(root, Guid.NewGuid().ToString("N"), "Импортированный сервер"));
        if (profiles.Count == 0) throw new ArgumentException("Не найдены профили Xray VLESS/REALITY.");
        if (profiles.Count > 500 || profiles.Select(p => p.Id).Distinct().Count() != profiles.Count) throw new ArgumentException("Некорректный список серверов.");
        return profiles;
    }

    private static ServerProfile ParseXray(JsonNode root, string id, string name)
    {
        var outbound = root["outbounds"]?.AsArray().FirstOrDefault(o => o?["protocol"]?.ToString() == "vless")
            ?? throw new ArgumentException("Требуется VLESS outbound.");
        var stream = outbound["streamSettings"] ?? throw new ArgumentException("Не найден transport.");
        if (stream["security"]?.ToString() != "reality" || stream["network"]?.ToString() is not ("tcp" or "raw"))
            throw new ArgumentException("Поддерживается VLESS + REALITY по TCP.");
        var server = outbound["settings"]?["vnext"]?[0] ?? throw new ArgumentException("Не найден сервер.");
        var user = server["users"]?[0] ?? throw new ArgumentException("Не найдены параметры доступа.");
        var reality = stream["realitySettings"]!;
        string Required(JsonNode node, string key)
        {
            var text = node[key]?.ToString();
            if (string.IsNullOrWhiteSpace(text) || text.Contains("REDACTED") || text.Length > 1024) throw new ArgumentException($"Отсутствует исходное поле {key}.");
            return text;
        }
        string address = Required(server, "address");
        if (Uri.CheckHostName(address) == UriHostNameType.Unknown) throw new ArgumentException("Некорректный адрес сервера.");
        int port = server["port"]?.GetValue<int>() ?? 0;
        if (port is < 1 or > 65535) throw new ArgumentException("Некорректный порт.");
        var uuid = Required(user, "id");
        // Xray also accepts short strings, mapped to UUIDv5 by the compatible VLESS engine.
        if (!Guid.TryParse(uuid, out _) && System.Text.Encoding.UTF8.GetByteCount(uuid) > 30)
            throw new ArgumentException("ID VLESS должен быть UUID или строкой до 30 байт.");
        var flow = user["flow"]?.ToString() ?? "";
        if (flow is not ("" or "xtls-rprx-vision")) throw new ArgumentException("Неподдерживаемый VLESS flow.");
        var shortId = reality["shortId"]?.ToString() ?? "";
        if (shortId.Length > 16 || shortId.Length % 2 != 0 || shortId.Any(c => !Uri.IsHexDigit(c))) throw new ArgumentException("Некорректный REALITY shortId.");
        var publicKey = Required(reality, "publicKey");
        try
        {
            if (Convert.FromBase64String(publicKey.Replace('-', '+').Replace('_', '/').PadRight((publicKey.Length + 3) / 4 * 4, '=')).Length != 32)
                throw new FormatException();
        }
        catch (FormatException) { throw new ArgumentException("REALITY publicKey должен содержать 32 байта X25519."); }
        return new(id, name, address, port, uuid, publicKey, shortId,
            Policy.NormalizeDomain(Required(reality, "serverName"), false), reality["fingerprint"]?.ToString() ?? "chrome", flow);
    }
}
