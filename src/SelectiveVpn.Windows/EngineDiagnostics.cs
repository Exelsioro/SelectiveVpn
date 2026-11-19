using System.Text.RegularExpressions;

namespace SelectiveVpn.Windows;

internal sealed partial class EngineDiagnostics(Action<string> publish)
{
    private const int ProcessHistoryLimit = 8192;
    private const int ProcessGroupLimit = 64;
    private const string ProcessPrefix = "router: found process path: ";
    private const string MissingProcess = "процесс не определён";
    private readonly object gate = new();
    private readonly Dictionary<string, string> processes = new();
    private readonly Queue<string> processOrder = new();
    private readonly Dictionary<string, (bool Direct, bool Reported)> resolutions = new();
    private readonly Queue<string> resolutionOrder = new();
    private readonly Dictionary<string, long> directTimeouts = new(StringComparer.OrdinalIgnoreCase);
    private long otherTimeouts;
    private long directDnsEmpty;

    public bool Record(string line)
    {
        var match = EngineLine().Match(line);
        if (!match.Success) return false;
        string level = match.Groups["level"].Value;
        string id = match.Groups["id"].Value;
        string body = match.Groups["body"].Value;

        if (level == "INFO" && id.Length > 0 && body.StartsWith(ProcessPrefix, StringComparison.Ordinal))
        {
            lock (gate)
            {
                if (!processes.ContainsKey(id))
                {
                    if (processOrder.Count == ProcessHistoryLimit) processes.Remove(processOrder.Dequeue());
                    processOrder.Enqueue(id);
                }
                processes[id] = Path.GetFileName(body[ProcessPrefix.Length..]);
            }
            return false;
        }
        if (level == "DEBUG" && id.Length > 0 && body.StartsWith("router: match", StringComparison.Ordinal)
            && body.Contains("=> resolve(", StringComparison.Ordinal))
        {
            lock (gate)
            {
                if (!resolutions.ContainsKey(id))
                {
                    if (resolutionOrder.Count == ProcessHistoryLimit) resolutions.Remove(resolutionOrder.Dequeue());
                    resolutionOrder.Enqueue(id);
                }
                resolutions[id] = (body.Contains("=> resolve(dns-direct,", StringComparison.Ordinal), false);
            }
            return false;
        }
        if (level is not ("ERROR" or "FATAL")) return false;
        if (level == "ERROR" && body.EndsWith(": empty result", StringComparison.Ordinal)
            && (body.StartsWith("dns: lookup failed for ", StringComparison.Ordinal)
                || body.StartsWith("router: lookup ", StringComparison.Ordinal)))
        {
            lock (gate)
            {
                if (resolutions.TryGetValue(id, out var resolution) && resolution.Direct)
                {
                    if (!resolution.Reported) directDnsEmpty++;
                    resolutions[id] = (true, true);
                    return false;
                }
            }
        }
        if (level == "ERROR" && body.Contains("using outbound/direct[direct]: lookup ", StringComparison.Ordinal)
            && body.EndsWith(": empty result", StringComparison.Ordinal))
        {
            lock (gate) directDnsEmpty++;
            return false;
        }

        if (level == "ERROR" && body.Contains("using outbound/direct[direct]: dial tcp ", StringComparison.Ordinal)
            && body.EndsWith(": i/o timeout", StringComparison.Ordinal))
        {
            lock (gate)
            {
                string app = processes.GetValueOrDefault(id, MissingProcess);
                if (directTimeouts.TryGetValue(app, out long count)) directTimeouts[app] = count + 1;
                else if (directTimeouts.Count < ProcessGroupLimit) directTimeouts.Add(app, 1);
                else otherTimeouts++;
            }
            return false;
        }

        publish("Движок: " + line);
        return true;
    }

    public void Flush(bool final = false)
    {
        string period = final ? "перед остановкой движка" : "за минуту";
        long dnsEmpty;
        lock (gate)
        {
            dnsEmpty = directDnsEmpty;
            directDnsEmpty = 0;
        }
        if (dnsEmpty > 0)
            publish($"Прямой DNS {period}: {dnsEmpty} ответов без адреса. Подробности в engine.log.");
        string message;
        lock (gate)
        {
            long total = directTimeouts.Values.Sum() + otherTimeouts;
            if (total == 0) return;
            var largest = directTimeouts.OrderByDescending(pair => pair.Value).Take(5).ToArray();
            var groups = largest.Select(pair => $"{pair.Key}: {pair.Value}").ToList();
            long remaining = total - largest.Sum(pair => pair.Value);
            if (remaining > 0) groups.Add($"прочие: {remaining}");
            directTimeouts.Clear();
            otherTimeouts = 0;

            message = $"Таймауты прямых TCP-соединений {period}: {total} ({string.Join(", ", groups)}). Подробности в engine.log.";
        }
        publish(message);
    }

    [GeneratedRegex(@"^(?:[+-]\d{4} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} )?(?<level>DEBUG|INFO|ERROR|FATAL)(?:\[\d+\])? +(?:\[(?<id>\d+) [^\]]+\] )?(?<body>.*)$",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture)]
    private static partial Regex EngineLine();
}
