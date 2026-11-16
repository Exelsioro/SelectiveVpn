using System.Diagnostics;
using System.Text;

namespace SelectiveVpn.Windows;

// Keep the adapter handle in a helper that matches the Wintun DLL architecture;
// closing stdin (including parent termination) releases the adapter.
public sealed class WintunAdapterProcess : IDisposable
{
    private Process? process;
    public async Task StartAsync(string dll, bool use64BitHelper, CancellationToken ct)
    {
        Dispose();
        var dllLiteral = dll.Replace("\"", "\"\"");
        string source = $$"""
        using System;
        using System.Runtime.InteropServices;
        public static class SelectiveWintun {
          [DllImport(@"{{dllLiteral}}", CharSet=CharSet.Unicode, SetLastError=true)]
          public static extern IntPtr WintunCreateAdapter(string name, string type, IntPtr guid);
          [DllImport(@"{{dllLiteral}}")]
          public static extern void WintunCloseAdapter(IntPtr handle);
        }
        """;
        string script = "$ErrorActionPreference='Stop'; Add-Type -TypeDefinition '" + source.Replace("'", "''") + "'; " +
            "$h=[SelectiveWintun]::WintunCreateAdapter('SelectiveVpn-OpenVPN','SelectiveVpn', [IntPtr]::Zero); " +
            "if($h -eq [IntPtr]::Zero) { throw ('WintunCreateAdapter: ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }; " +
            "try { [Console]::WriteLine('READY'); [Console]::Out.Flush(); [Console]::ReadLine() | Out-Null } finally { [SelectiveWintun]::WintunCloseAdapter($h) }";
        var info = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), use64BitHelper ? "System32" : "SysWOW64", "WindowsPowerShell", "v1.0", "powershell.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }) info.ArgumentList.Add(arg);
        process = Process.Start(info)!;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromSeconds(20));
        var errors = process.StandardError.ReadToEndAsync();
        try
        {
            if (await process.StandardOutput.ReadLineAsync(timeout.Token) != "READY") throw new IOException("Создание адаптера OpenVPN: " + await errors);
        }
        catch { Dispose(); throw; }
    }
    public void Dispose()
    {
        if (process is null) return;
        try
        {
            process.StandardInput.Close();
            if (!process.WaitForExit(5000)) { process.Kill(true); process.WaitForExit(3000); }
        }
        finally { process.Dispose(); process = null; }
    }
}
