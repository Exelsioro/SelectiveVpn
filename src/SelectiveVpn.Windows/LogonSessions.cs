using System.ComponentModel;
using System.Runtime.InteropServices;
namespace SelectiveVpn.Windows;
public static class LogonSessions
{
    [StructLayout(LayoutKind.Sequential)] private struct Session { public int Id; public IntPtr Station; public int State; }
    [DllImport("wtsapi32.dll", EntryPoint="WTSEnumerateSessionsW", SetLastError=true)] private static extern bool Enumerate(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("wtsapi32.dll", EntryPoint="WTSQuerySessionInformationW", SetLastError=true)] private static extern bool Query(IntPtr server, int session, int info, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr memory);
    public static HashSet<int> Read()
    {
        if (!Enumerate(IntPtr.Zero, 0, 1, out var pointer, out var count)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            var result = new HashSet<int>();
            for (int i=0; i<count; i++) {
                var session=Marshal.PtrToStructure<Session>(pointer+i*Marshal.SizeOf<Session>());
                if (session.Id==0 || !Query(IntPtr.Zero,session.Id,5,out var name,out _)) continue;
                try { if (!string.IsNullOrWhiteSpace(Marshal.PtrToStringUni(name))) result.Add(session.Id); }
                finally { WTSFreeMemory(name); }
            }
            return result;
        } finally { WTSFreeMemory(pointer); }
    }
}
