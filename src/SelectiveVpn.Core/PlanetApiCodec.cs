using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace SelectiveVpn.Core;

public static class PlanetApiCodec
{
    public static JsonObject Decode(string json, string keyBase64)
    {
        var payload = JsonNode.Parse(json)?["payload"]?.GetValue<string>() ?? throw new InvalidDataException("API не вернул payload.");
        var envelope = JsonNode.Parse(Convert.FromBase64String(payload))!;
        string iv = envelope["iv"]!.GetValue<string>(), value = envelope["value"]!.GetValue<string>();
        byte[] key = Convert.FromBase64String(keyBase64);
        byte[] expected = Convert.FromHexString(envelope["mac"]!.GetValue<string>());
        byte[] actual = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(iv + value));
        if (!CryptographicOperations.FixedTimeEquals(actual, expected)) throw new InvalidDataException("Неверная подпись ответа PlanetVPN.");
        using var aes = Aes.Create(); aes.Key = key;
        byte[] decoded = aes.DecryptCbc(Convert.FromBase64String(value), Convert.FromBase64String(iv), PaddingMode.PKCS7);
        try { return JsonNode.Parse(decoded)!.AsObject(); }
        finally { CryptographicOperations.ZeroMemory(decoded); CryptographicOperations.ZeroMemory(key); }
    }

    public static ServerProfile ParseNode(JsonObject response, int poolId, string location, string country)
    {
        var node = response["data"] ?? throw new InvalidDataException("API не вернул узел.");
        if (node is JsonArray list) node = list.FirstOrDefault() ?? throw new InvalidDataException("Пустой пул.");
        string xray = node["xray_config"]?.ToString() ?? "";
        ServerProfile profile = !string.IsNullOrWhiteSpace(xray)
            ? PlanetProfileImporter.Import(xray).Single()
            : new("", "", node["ip_address"]!.ToString(), 443, "", "", "", "", "", "");
        var configs = new Dictionary<VpnProtocol, string>();
        foreach (var (protocol, field) in new[] { (VpnProtocol.OpenVpnUdp, "ovpn_config_udp"), (VpnProtocol.OpenVpnTcp, "ovpn_config_tcp"), (VpnProtocol.OpenVpnXorUdp, "ovpn_config_udp_xor"), (VpnProtocol.OpenVpnXorTcp, "ovpn_config_tcp_xor") })
        {
            var text = node[field]?.ToString();
            if (!string.IsNullOrWhiteSpace(text)) configs[protocol] = OpenVpnConfiguration.Validate(text + "\n" + node["ovpn_config_cert"]?.ToString());
        }
        return profile with { Id = "pool-" + poolId, PoolId = poolId, Country = country,
            Name = location + " · " + node["city"]?.ToString(), OpenVpnConfigs = configs,
            AccessUser = node["access_user"]?.ToString() ?? "", AccessKey = node["access_key"]?.ToString() ?? "" };
    }
}
