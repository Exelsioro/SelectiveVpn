using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.IO;
namespace SelectiveVpn.App;
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var window = new MainWindow();
        if (e.Args.Length == 2 && e.Args[0] == "--smoke-render")
        {
            var content = (FrameworkElement)window.Content;
            content.Measure(new Size(1072, 752));
            content.Arrange(new Rect(0, 0, 1072, 752));
            content.UpdateLayout();
            var bitmap = new RenderTargetBitmap(1072, 752, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(content);
            var png = new PngBitmapEncoder(); png.Frames.Add(BitmapFrame.Create(bitmap));
            using (var file = File.Create(e.Args[1])) png.Save(file);
            Shutdown(0);
            return;
        }
        MainWindow = window;
        if (e.Args.Contains("--tray")) window.StartInTray();
        else window.Show();
    }
}
