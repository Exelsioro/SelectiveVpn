using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using SelectiveVpn.App;
using SelectiveVpn.Core;
using Forms = System.Windows.Forms;
internal static class Program
{
    private static int passed;
    private static void Check(bool condition, string text) { if (!condition) throw new Exception(text); passed++; Console.WriteLine("PASS " + text); }
    private static object Field(object obj, string name) => obj.GetType().GetField(name, BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(obj)!;
    [STAThread] private static int Main()
    {
        int code=1;
        var app=new Application { ShutdownMode=ShutdownMode.OnExplicitShutdown };
        var window=new MainWindow(); window.Show();
        app.Dispatcher.InvokeAsync(async () => {
            try {
                await Task.Delay(1000);
                var input=(TextBox)window.FindName("ValueBox"); input.Text="unsaved-tray.example";
                typeof(MainWindow).GetField("dirty", BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(window,true);
                window.Close();
                Check(!window.IsVisible && input.Text=="unsaved-tray.example", "Cross hides window and preserves unsaved draft");
                var actualTray=Field(window,"tray");
                var actualIcon=(Forms.NotifyIcon)Field(actualTray,"icon");
                Check(actualIcon.Visible,"Tray remains visible after window close");
                typeof(Forms.NotifyIcon).GetMethod("OnDoubleClick",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(actualIcon,[EventArgs.Empty]);
                Check(window.IsVisible,"Double click restores UI");
                int opened=0,connected=0,disconnected=0,exited=0;
                var type=actualTray.GetType();
                using var isolated=(IDisposable)Activator.CreateInstance(type,(Action)(()=>opened++),(Action)(()=>connected++),(Action)(()=>disconnected++),(Action)(()=>exited++))!;
                var icon=(Forms.NotifyIcon)Field(isolated,"icon");
                var connect=(Forms.ToolStripMenuItem)Field(isolated,"connect");
                var disconnect=(Forms.ToolStripMenuItem)Field(isolated,"disconnect");
                var update=type.GetMethod("Update")!;
                update.Invoke(isolated,[TunnelState.Disconnected,false]); var offlineIcon=icon.Icon;
                Check(connect.Enabled && !disconnect.Enabled,"Offline menu enables only connect"); connect.PerformClick();
                update.Invoke(isolated,[TunnelState.Connected,false]);
                Check(icon.Icon!=offlineIcon && !connect.Enabled && disconnect.Enabled,"Connected icon and actions update"); disconnect.PerformClick();
                update.Invoke(isolated,[TunnelState.Connecting,false]); Check(!connect.Enabled && disconnect.Enabled,"Connecting remains cancellable");
                update.Invoke(isolated,[TunnelState.Faulted,false]); Check(icon.Text.Contains("Ошибка"),"Fault shown in tooltip");
                update.Invoke(isolated,[null,false]); Check(icon.Text.Contains("недоступна") && connect.Enabled,"Unavailable service shown correctly");
                update.Invoke(isolated,[TunnelState.Connected,true]); Check(!connect.Enabled && !disconnect.Enabled,"Duplicate commands disabled while busy");
                var menu=(Forms.ContextMenuStrip)Field(isolated,"menu");
                ((Forms.ToolStripMenuItem)menu.Items[0]).PerformClick(); ((Forms.ToolStripMenuItem)menu.Items[5]).PerformClick();
                Check(opened==1 && connected==1 && disconnected==1 && exited==1,"All tray actions invoke correct callbacks");
                typeof(MainWindow).GetField("dirty",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(window,false);
                typeof(MainWindow).GetMethod("ExitFromTray",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(window,null);
                Check(!actualIcon.Visible,"Exit removes tray icon");
                Console.WriteLine($"{passed} tray checks passed; no connect/disconnect commands sent to service."); code=0;
            } catch(Exception ex) {Console.Error.WriteLine(ex);}
            finally {app.Shutdown();}
        });
        app.Run();return code;
    }
}
