using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using Forms = System.Windows.Forms;
using SelectiveVpn.Core;
namespace SelectiveVpn.App;

internal sealed class TrayController : IDisposable
{
    private readonly Forms.NotifyIcon icon;
    private readonly Forms.ContextMenuStrip menu = new();
    private readonly Forms.ToolStripMenuItem connect, disconnect;
    private readonly Dictionary<string, Icon> icons = new();
    public TrayController(Action show, Action connectAction, Action disconnectAction, Action exit)
    {
        icons["offline"] = MakeIcon(Color.SlateGray, "–");
        icons["online"] = MakeIcon(Color.ForestGreen, "✓");
        icons["busy"] = MakeIcon(Color.DarkOrange, "…");
        icons["error"] = MakeIcon(Color.Firebrick, "!");
        menu.Items.Add("Открыть", null, (_, _) => show());
        menu.Items.Add(new Forms.ToolStripSeparator());
        connect = new("Подключить", null, (_, _) => connectAction()); menu.Items.Add(connect);
        disconnect = new("Отключить", null, (_, _) => disconnectAction()); menu.Items.Add(disconnect);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Выход", null, (_, _) => exit());
        icon = new Forms.NotifyIcon { Icon = icons["offline"], Text = "SelectiveVpn — проверка состояния", ContextMenuStrip = menu, Visible = true };
        icon.DoubleClick += (_, _) => show();
    }
    public void Update(TunnelState? state, bool commandBusy)
    {
        var (key, text) = state switch
        {
            TunnelState.Connected => ("online", "VPN подключён"),
            TunnelState.Connecting => ("busy", "Подключение VPN"),
            TunnelState.Starting => ("busy", "Запуск службы"),
            TunnelState.Stopping => ("busy", "Остановка"),
            TunnelState.Faulted => ("error", "Ошибка VPN / ожидание переподключения"),
            TunnelState.Disconnected => ("offline", "VPN отключён"),
            _ => ("offline", "Служба недоступна")
        };
        if (icon.Icon != icons[key]) icon.Icon = icons[key];
        icon.Text = "SelectiveVpn — " + text;
        connect.Enabled = !commandBusy && state is not (TunnelState.Connected or TunnelState.Connecting or TunnelState.Starting or TunnelState.Stopping);
        disconnect.Enabled = !commandBusy && state is TunnelState.Connected or TunnelState.Connecting or TunnelState.Faulted;
    }
    private static Icon MakeIcon(Color color, string label)
    {
        using var bitmap = new Bitmap(32, 32);
        using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        graphics.Clear(Color.Transparent);
        using var brush = new SolidBrush(color);
        graphics.FillEllipse(brush, 1, 1, 30, 30);
        using var font = new Font("Segoe UI", 19, FontStyle.Bold, GraphicsUnit.Pixel);
        using var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        graphics.DrawString(label, font, Brushes.White, new RectangleF(0, 0, 32, 31), format);
        var handle = bitmap.GetHicon();
        try { using var borrowed = Icon.FromHandle(handle); return (Icon)borrowed.Clone(); }
        finally { DestroyIcon(handle); }
    }
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    public void Dispose()
    {
        icon.Visible = false; icon.Dispose(); menu.Dispose();
        foreach (var value in icons.Values) value.Dispose();
    }
}
