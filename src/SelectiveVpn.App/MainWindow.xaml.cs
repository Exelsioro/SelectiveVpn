using System.Collections.ObjectModel;
using System.IO;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using SelectiveVpn.Core;
using SelectiveVpn.Windows;

namespace SelectiveVpn.App;

public partial class MainWindow : Window
{
    private sealed record Option<T>(T Value, string Label);
    public sealed record RuleRow(RoutingRule Rule)
    {
        public string KindLabel => Rule.Kind switch { RuleKind.Application => "Приложение", RuleKind.Domain => "Домен", RuleKind.DomainSuffix => "Домен и поддомены", _ => "IP / CIDR" };
        public string TargetLabel => Rule.Target == RouteTarget.Vpn ? "Через VPN" : "Напрямую";
    }
    private readonly ObservableCollection<RuleRow> rows = [];
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(3) };
    private bool busy, loading, initialized, dirty, serviceOperation;
    private ClientSettings current = new();

    public MainWindow()
    {
        InitializeComponent();
        KindBox.ItemsSource = new[] { new Option<RuleKind>(RuleKind.DomainSuffix, "Домен и поддомены"), new(RuleKind.Domain, "Точный домен"), new(RuleKind.IpCidr, "IP / CIDR"), new(RuleKind.Application, "Приложение") };
        var targets = new[] { new Option<RouteTarget>(RouteTarget.Vpn, "Через VPN"), new(RouteTarget.Direct, "Напрямую") };
        TargetBox.ItemsSource = targets; DefaultBox.ItemsSource = targets;
        KindBox.SelectedIndex = 0; TargetBox.SelectedIndex = 0;
        ProtocolBox.ItemsSource = new[] { new Option<VpnProtocol>(VpnProtocol.Auto, "Авто — перебор доступных протоколов"), new(VpnProtocol.VlessReality, "VLESS / REALITY"), new(VpnProtocol.OpenVpnUdp, "OpenVPN UDP"), new(VpnProtocol.OpenVpnTcp, "OpenVPN TCP"), new(VpnProtocol.OpenVpnXorUdp, "OpenVPN XOR UDP"), new(VpnProtocol.OpenVpnXorTcp, "OpenVPN XOR TCP") };
        RulesGrid.ItemsSource = rows;
        Loaded += async (_, _) => { await RefreshAsync(); timer.Start(); };
        timer.Tick += async (_, _) => await RefreshAsync();
        Closing += (_, e) =>
        {
            if (dirty && MessageBox.Show("Несохранённые изменения будут потеряны. Закрыть окно?", "SelectiveVpn", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) e.Cancel = true;
        };
        Closed += (_, _) => timer.Stop();
    }
    private async Task RefreshAsync()
    {
        if (busy) return;
        await InvokeAsync(new("status"), false);
    }
    private async Task<bool> InvokeAsync(RpcRequest request, bool showError = true, bool reload = false)
    {
        if (busy) return false;
        busy = true;
        ServersBox.IsEnabled = false;
        ProtocolBox.IsEnabled = false;
        SaveButton.IsEnabled = false;
        RuleEditor.IsEnabled = RuleActions.IsEnabled = false;
        try
        {
            var response = await PipeRpc.CallAsync(request);
            if (response.Status is { } status)
            {
                StatusText.Text = status.Message;
                ProtectionText.Text = status.ProtectionActive ? $"Защищено приложений: {status.ProtectedApplications}" : "Защита не подтверждена";
                EventsBox.Text = string.Join(Environment.NewLine, status.Events.Reverse());
                if (!initialized || reload) LoadSettings(status);
            }
            if (!response.Success) throw new InvalidOperationException(response.Error);
            return true;
        }
        catch (Exception ex)
        {
            StatusText.Text = request.Command == "status" ? "Служба остановлена или недоступна. Нажмите «Запустить службу». Защищённые приложения остаются заблокированными." : ex.Message;
            if (showError) MessageBox.Show(ex.Message, "SelectiveVpn", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }
        finally { RuleEditor.IsEnabled = RuleActions.IsEnabled = true; busy = false; ProtocolBox.IsEnabled = initialized; ServersBox.IsEnabled = initialized; SaveButton.IsEnabled = initialized; }
    }
    private void LoadSettings(StatusSnapshot status)
    {
        loading = true;
        current = Wire.Clone(status.Settings);
        rows.Clear(); foreach (var rule in current.Rules) rows.Add(new(rule));
        ServersBox.ItemsSource = status.Servers; ServersBox.SelectedValue = current.SelectedServerId;
        if (ServersBox.SelectedValue is null) ServersBox.SelectedValue = "recommended";
        ProtocolBox.SelectedValue = current.Protocol;
        DefaultBox.SelectedValue = current.DefaultRoute; AutoConnectBox.IsChecked = current.AutoConnect;
        initialized = true; loading = false; dirty = false; SetTitle();
    }
    private ClientSettings ReadSettings() => Policy.Normalize(current with
    {
        SelectedServerId = ServersBox.SelectedValue as string,
        DefaultRoute = DefaultBox.SelectedValue is RouteTarget target ? target : RouteTarget.Direct,
        AutoConnect = AutoConnectBox.IsChecked == true,
        Protocol = ProtocolBox.SelectedValue is VpnProtocol protocol ? protocol : VpnProtocol.Auto,
        Rules = rows.Select(r => r.Rule).ToList()
    });
    private async Task<bool> SaveAsync()
    {
        try { return await InvokeAsync(new("save", ReadSettings()), reload: true); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Проверьте правило"); return false; }
    }
    private async void Save_Click(object sender, RoutedEventArgs e) => await SaveAsync();
    private async void Connect_Click(object sender, RoutedEventArgs e)
    { if (!initialized || busy) return; if (dirty && !await SaveAsync()) return; await InvokeAsync(new("connect")); }
    private async void Disconnect_Click(object sender, RoutedEventArgs e) => await InvokeAsync(new("disconnect"));
    private async void Protocol_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (loading || !initialized || busy || ProtocolBox.SelectedValue is not VpnProtocol protocol || protocol == current.Protocol) return;
        var previous = current.Protocol;
        if (await InvokeAsync(new("select-protocol", Protocol: protocol))) current.Protocol = protocol;
        else { loading = true; ProtocolBox.SelectedValue = previous; loading = false; }
    }
    private async void StopService_Click(object sender, RoutedEventArgs e)
    {
        if (serviceOperation) return;
        serviceOperation = true;
        StartServiceButton.IsEnabled = StopServiceButton.IsEnabled = false;
        try { await ServiceControl.StopAsync(); StatusText.Text = "Служба остановлена. TUN выключен; блокировки выбранных приложений сохранены."; }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Остановка службы"); }
        finally { serviceOperation = false; StartServiceButton.IsEnabled = StopServiceButton.IsEnabled = true; }
    }
    private async void StartService_Click(object sender, RoutedEventArgs e)
    {
        if (serviceOperation) return;
        serviceOperation = true;
        StartServiceButton.IsEnabled = StopServiceButton.IsEnabled = false;
        try { await ServiceControl.StartAsync(); await RefreshAsync(); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Запуск службы"); }
        finally { serviceOperation = false; StartServiceButton.IsEnabled = StopServiceButton.IsEnabled = true; }
    }
    private async void RefreshServers_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        if (dirty && !await SaveAsync()) return;
        await InvokeAsync(new("refresh"), reload: true);
    }
    private void OpenLog_Click(object sender, RoutedEventArgs e)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SelectiveVpn", "service.log");
        try { var info = new ProcessStartInfo("notepad.exe") { UseShellExecute = true }; info.ArgumentList.Add(path); Process.Start(info); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Журнал"); }
    }
    private async void Server_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (loading || !initialized || busy || ServersBox.SelectedValue is not string id || id == current.SelectedServerId) return;
        string? previous = current.SelectedServerId;
        if (await InvokeAsync(new("select-server", ServerId: id))) current.SelectedServerId = id;
        else { loading = true; ServersBox.SelectedValue = previous; loading = false; }
    }
    private async void Import_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        var dialog = new OpenFileDialog { Filter = "Профили PlanetVPN / Xray (*.json)|*.json", Title = "Импорт decoded-payload.json или Xray-конфига" };
        if (dialog.ShowDialog() != true) return;
        try
        {
            if (new FileInfo(dialog.FileName).Length > 4_000_000) throw new InvalidDataException("Слишком большой файл.");
            if (dirty && !await SaveAsync()) return;
            await InvokeAsync(new("import", ImportJson: await File.ReadAllTextAsync(dialog.FileName)), reload: true);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Ошибка импорта"); }
    }
    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "Приложение Windows (*.exe)|*.exe" };
        if (dialog.ShowDialog() == true) { ValueBox.Text = dialog.FileName; KindBox.SelectedValue = RuleKind.Application; }
    }
    private void Add_Click(object sender, RoutedEventArgs e)
    {
        if (!initialized) return;
        try
        {
            var rule = new RoutingRule { Kind = (RuleKind)KindBox.SelectedValue, Target = (RouteTarget)TargetBox.SelectedValue, Value = ValueBox.Text };
            var draft = ReadSettings(); draft.Rules.Add(rule); draft = Policy.Normalize(draft);
            rows.Add(new(draft.Rules[^1])); ValueBox.Clear(); MarkDirty();
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Проверьте правило"); }
    }
    private void Remove_Click(object sender, RoutedEventArgs e) { if (RulesGrid.SelectedItem is RuleRow row) { rows.Remove(row); MarkDirty(); } }
    private void Toggle_Click(object sender, RoutedEventArgs e)
    { if (RulesGrid.SelectedItem is RuleRow row) { row.Rule.Enabled = !row.Rule.Enabled; RulesGrid.Items.Refresh(); MarkDirty(); } }
    private void Up_Click(object sender, RoutedEventArgs e) => Move(-1);
    private void Down_Click(object sender, RoutedEventArgs e) => Move(1);
    private void Move(int delta)
    { int index = RulesGrid.SelectedIndex; if (index >= 0 && index + delta >= 0 && index + delta < rows.Count) { rows.Move(index, index + delta); RulesGrid.SelectedIndex = index + delta; MarkDirty(); } }
    private void Changed(object sender, RoutedEventArgs e) { if (!loading && initialized) MarkDirty(); }
    private void MarkDirty() { dirty = true; SetTitle(); }
    private void SetTitle() => Title = "SelectiveVpn — маршрутизация приложений" + (dirty ? " • не сохранено" : "");
}
