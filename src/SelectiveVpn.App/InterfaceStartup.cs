using System.IO;
using System.Security.Principal;
using SelectiveVpn.Windows;
namespace SelectiveVpn.App;
internal static class InterfaceStartup
{
    private static string Sid => WindowsIdentity.GetCurrent().User!.Value;
    private static string Quote(string value) => "'" + value.Replace("'", "''") + "'";
    public static string TaskName => "SelectiveVpn.UI." + Sid;
    public static async Task<bool> IsEnabledAsync() => (await HostNetwork.PowerShellAsync(
        "$t=Get-ScheduledTask | Where-Object TaskName -eq " + Quote(TaskName) + "; if($t -and $t.State -ne 'Disabled') {'enabled'}", CancellationToken.None)).Trim()=="enabled";
    public static async Task SetEnabledAsync(bool enabled)
    {
        string task=Quote(TaskName);
        if (!enabled) { await HostNetwork.PowerShellAsync("Get-ScheduledTask | Where-Object TaskName -eq " + task + " | Unregister-ScheduledTask -Confirm:$false", CancellationToken.None); return; }
        string exe=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SelectiveVpn", "App", "SelectiveVpn.App.exe");
        if (!File.Exists(exe)) throw new FileNotFoundException("Сначала установите клиент.",exe);
        await HostNetwork.PowerShellAsync("$ProgressPreference='SilentlyContinue'; $action=New-ScheduledTaskAction -Execute " + Quote(exe) + " -Argument '--tray'; " +
            "$trigger=New-ScheduledTaskTrigger -AtLogOn -User " + Quote(WindowsIdentity.GetCurrent().Name) + "; " +
            "$principal=New-ScheduledTaskPrincipal -UserId " + Quote(WindowsIdentity.GetCurrent().Name) + " -LogonType Interactive -RunLevel Highest; " +
            "$settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew; " +
            "Register-ScheduledTask -TaskName " + task + " -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'SelectiveVpn interface at logon, hidden in notification area' -Force | Out-Null", CancellationToken.None);
    }
}
