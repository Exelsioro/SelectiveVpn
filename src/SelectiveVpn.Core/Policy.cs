using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace SelectiveVpn.Core;

public static class Policy
{
    public static ClientSettings Normalize(ClientSettings input)
    {
        if (input.SchemaVersion != 1 || !Enum.IsDefined(input.DefaultRoute)) throw new ArgumentException("Неподдерживаемая версия настроек.");
        var result = Wire.Clone(input);
        if (result.Rules is null || result.Rules.Count > 1000) throw new ArgumentException("Допустимо до 1000 правил.");
        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ids = new HashSet<Guid>();
        foreach (var rule in result.Rules)
        {
            if (!Enum.IsDefined(rule.Kind) || !Enum.IsDefined(rule.Target)) throw new ArgumentException("Неизвестный вид правила.");
            if (rule.Id == Guid.Empty || !ids.Add(rule.Id)) throw new ArgumentException("Повторяющийся идентификатор правила.");
            var value = rule.Value?.Trim() ?? "";
            rule.Value = rule.Kind switch
            {
                RuleKind.Application => NormalizeApplication(value),
                RuleKind.Domain => NormalizeDomain(value, false),
                RuleKind.DomainSuffix => NormalizeDomain(value, true),
                RuleKind.IpCidr => NormalizeCidr(value),
                _ => throw new ArgumentException("Неизвестный вид правила.")
            };
            if (rule.Enabled && !identities.Add($"{rule.Kind}:{rule.Value}"))
                throw new ArgumentException($"Повторяющееся правило: {rule.Value}");
        }
        return result;
    }

    public static string NormalizeApplication(string value)
    {
        if (!Path.IsPathFullyQualified(value) || value.StartsWith(@"\\", StringComparison.Ordinal) ||
            !value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Для приложения нужен полный локальный путь к .exe.");
        var path = Path.GetFullPath(value);
        if (path[2..].Contains(':')) throw new ArgumentException("Потоки NTFS не поддерживаются.");
        return path;
    }

    public static string NormalizeDomain(string value, bool suffix)
    {
        if (suffix && value.StartsWith("*.")) value = value[2..];
        value = value.TrimEnd('.');
        if (value.Contains('/') || value.Contains(':') || value.Contains('*') || IPAddress.TryParse(value, out _))
            throw new ArgumentException("Введите домен без протокола, порта и пути; IP задаётся отдельным правилом.");
        try { value = new IdnMapping().GetAscii(value).ToLowerInvariant(); }
        catch (ArgumentException) { throw new ArgumentException("Недопустимый домен."); }
        if (value.Length is < 1 or > 253 || value.Split('.').Any(p => !Regex.IsMatch(p, @"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")))
            throw new ArgumentException("Недопустимый домен.");
        return value;
    }

    public static string NormalizeCidr(string value)
    {
        var parts = value.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address)) throw new ArgumentException("Некорректный IP или CIDR.");
        var bytes = address.GetAddressBytes();
        int bits = bytes.Length * 8;
        int prefix = bits;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix < 0 || prefix > bits))
            throw new ArgumentException("Некорректная длина маски CIDR.");
        for (int i = 0; i < bytes.Length; i++) bytes[i] &= (byte)(0xff << Math.Clamp(8 - (prefix - i * 8), 0, 8));
        return $"{new IPAddress(bytes)}/{prefix}";
    }

    public static IEnumerable<RoutingRule> Ordered(ClientSettings settings) => settings.Rules.Where(r => r.Enabled)
        .OrderBy(r => r.Kind == RuleKind.Application && r.Target == RouteTarget.Vpn ? 0 : r.Kind == RuleKind.Application ? 1 : r.Kind == RuleKind.IpCidr ? 3 : 2);

    // RE2 does not accept .NET's escaped spaces.
    public static string ProcessRegex(string path) => "(?i)^" + Regex.Replace(path, @"[\\.\[\]{}()*+?^$|]", @"\$0") + "$";
}
