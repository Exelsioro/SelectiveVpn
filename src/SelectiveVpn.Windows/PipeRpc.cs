using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SelectiveVpn.Core;

namespace SelectiveVpn.Windows;

public static class PipeRpc
{
    private const int MaxFrame = 5 * 1024 * 1024;
    public static NamedPipeServerStream CreateServer()
    {
        var acl = new PipeSecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new(new SecurityIdentifier(sid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        return NamedPipeServerStreamAcl.Create(Wire.PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 65536, 65536, acl);
    }
    public static async Task<RpcResponse> CallAsync(RpcRequest request, CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(70));
        await using var pipe = new NamedPipeClientStream(".", Wire.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(2500, timeout.Token);
        VerifyServer(pipe.SafePipeHandle);
        await WriteAsync(pipe, request, timeout.Token);
        return await ReadAsync<RpcResponse>(pipe, timeout.Token);
    }
    private static void VerifyServer(SafePipeHandle pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe, out uint pid)) throw new Win32Exception(Marshal.GetLastWin32Error());
        using var process = OpenProcess(0x1000, false, pid);
        if (process.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var buffer = new StringBuilder(32768); uint size = (uint)buffer.Capacity;
        if (!QueryFullProcessImageNameW(process, 0, buffer, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
        string expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SelectiveVpn", "Service", "SelectiveVpn.Service.exe");
        if (!buffer.ToString().Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Канал управления принадлежит неизвестному процессу. Используйте установленную службу SelectiveVpn.");
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, StringBuilder path, ref uint size);
    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is < 1 or > MaxFrame) throw new InvalidDataException("Invalid RPC frame length.");
        var data = new byte[length];
        await stream.ReadExactlyAsync(data, ct);
        return JsonSerializer.Deserialize<T>(data, Wire.Json) ?? throw new InvalidDataException("Empty RPC request.");
    }
    public static async Task WriteAsync<T>(Stream stream, T value, CancellationToken ct)
    {
        var data = JsonSerializer.SerializeToUtf8Bytes(value, Wire.Json);
        if (data.Length > MaxFrame) throw new InvalidDataException("RPC message too large.");
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, data.Length);
        await stream.WriteAsync(header, ct);
        await stream.WriteAsync(data, ct);
        await stream.FlushAsync(ct);
    }
}
