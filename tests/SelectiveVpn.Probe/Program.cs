using System.Net;
using System.Net.Sockets;

Console.OutputEncoding = System.Text.Encoding.UTF8;
if (args.Length < 2) return 2;
try
{
    if (args[0] == "--https")
    {
        string hostname = args[1]; var destination = IPAddress.Parse(args[2]);
        using var handler = new SocketsHttpHandler { UseProxy = false };
        handler.ConnectCallback = async (_, cancellation) =>
        {
            var socket = new Socket(destination.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try { await socket.ConnectAsync(destination, 443, cancellation); return new NetworkStream(socket, true); }
            catch { socket.Dispose(); throw; }
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        string result = await client.GetStringAsync($"https://{hostname}/cdn-cgi/trace");
        Console.WriteLine(string.Join(" ", result.Split('\n').Where(l => l.StartsWith("ip=") || l.StartsWith("loc="))));
        return 0;
    }
    var ip = IPAddress.Parse(args[0]);
    bool udp = args.Contains("--udp");
    using var socket = new Socket(ip.AddressFamily, udp ? SocketType.Dgram : SocketType.Stream, udp ? ProtocolType.Udp : ProtocolType.Tcp);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    await socket.ConnectAsync(new IPEndPoint(ip, int.Parse(args[1])), timeout.Token);
    if (udp) { await socket.SendAsync(new byte[] { 42 }, timeout.Token); await socket.ReceiveAsync(new byte[16], timeout.Token); }
    Console.WriteLine("CONNECTED");
    if (args.Contains("--hold")) await Task.Delay(15000);
    return 0;
}
catch (SocketException ex) { Console.WriteLine(ex.SocketErrorCode); return ex.SocketErrorCode == SocketError.AccessDenied ? 10 : 11; }
catch (HttpRequestException ex) { Console.WriteLine(ex.Message); return ex.InnerException is SocketException { SocketErrorCode: SocketError.AccessDenied } ? 10 : 11; }
catch (OperationCanceledException) { Console.WriteLine("TIMEOUT"); return 12; }
