namespace SelectiveVpn.Core;

public static class OpenVpnConfiguration
{
    private static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase)
    { "client", "dev", "proto", "remote", "resolv-retry", "nobind", "persist-key", "persist-tun", "remote-cert-tls", "verify-x509-name", "tls-version-min", "tls-version-max", "reneg-sec", "sndbuf", "rcvbuf", "fast-io", "float", "mute", "pull", "tls-cipher", "tls-ciphersuites", "verb", "cipher", "data-ciphers", "data-ciphers-fallback", "auth", "key-direction", "scramble", "auth-nocache", "tun-mtu", "mssfix", "explicit-exit-notify", "remote-random", "connect-timeout", "connect-retry", "connect-retry-max" };
    public static string Validate(string text)
    {
        if (text.Length > 100_000) throw new InvalidDataException("OpenVPN-конфигурация слишком большая.");
        string? block = null;
        var lines = new List<string>();
        foreach (string raw in text.Replace("\r", "").Split('\n'))
        {
            string line = raw.Trim();
            if (block is not null)
            {
                if (line == "</" + block + ">") block = null;
                else if (line.StartsWith('<')) throw new InvalidDataException("Некорректный inline-блок.");
                lines.Add(line); continue;
            }
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
            if (line is "<ca>" or "<cert>" or "<key>" or "<tls-crypt>" or "<tls-auth>" or "<tls-crypt-v2>" or "<auth-user-pass>") { block = line[1..^1]; lines.Add(line); continue; }
            string keyword = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[0];
            if (!Allowed.Contains(keyword)) throw new InvalidDataException("Недопустимая директива OpenVPN: " + keyword);
            // Lifecycle and verbosity are controlled by our service.
            if (keyword is "persist-tun" or "verb" or "resolv-retry") continue;
            lines.Add(line);
        }
        if (block is not null) throw new InvalidDataException("Незавершённый inline-блок OpenVPN.");
        if (!lines.Any(l => l.StartsWith("remote ")) || !lines.Contains("<ca>")) throw new InvalidDataException("OpenVPN: отсутствует remote или CA.");
        return string.Join('\n', lines) + "\n";
    }
}
