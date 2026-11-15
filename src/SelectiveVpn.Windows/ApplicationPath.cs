using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SelectiveVpn.Core;

namespace SelectiveVpn.Windows;

public static class ApplicationPath
{
    public static string Canonicalize(string path)
    {
        path = Policy.NormalizeApplication(path);
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var buffer = new StringBuilder(32768);
        uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error());
        var result = buffer.ToString();
        if (result.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Сетевые исполняемые файлы не поддерживаются.");
        if (result.StartsWith(@"\\?\", StringComparison.Ordinal)) result = result[4..];
        return Policy.NormalizeApplication(result);
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);
}
