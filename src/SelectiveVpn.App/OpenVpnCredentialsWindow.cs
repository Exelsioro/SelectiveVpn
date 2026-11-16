using System.Windows;
using System.Windows.Controls;

namespace SelectiveVpn.App;

internal sealed class OpenVpnCredentialsWindow : Window
{
    private readonly TextBox user = new() { MinHeight = 32 };
    private readonly PasswordBox password = new() { MinHeight = 32 };

    public string Username => user.Text;
    public string Password => password.Password;

    public OpenVpnCredentialsWindow(Window owner)
    {
        Owner = owner;
        Title = "Доступ к OpenVPN";
        Width = 390;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = owner.Background;
        Foreground = owner.Foreground;
        FontFamily = owner.FontFamily;
        FontSize = owner.FontSize;
        var form = new StackPanel { Margin = new Thickness(20) };
        form.Children.Add(new TextBlock
        {
            Text = "Укажи логин и пароль из кабинета VPN-провайдера.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8)
        });
        form.Children.Add(new Label { Content = "Логин", Target = user });
        form.Children.Add(user);
        form.Children.Add(new Label { Content = "Пароль", Target = password, Margin = new Thickness(0, 6, 0, 0) });
        form.Children.Add(password);
        var actions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 16, 0, 0) };
        var cancel = new Button { Content = "Отмена", IsCancel = true, Margin = new Thickness(0, 0, 8, 0),
            Style = (Style)owner.FindResource("CommandButton") };
        var submit = new Button { Content = "Добавить", IsDefault = true, IsEnabled = false,
            Style = (Style)owner.FindResource("PrimaryButton") };
        void Update(object sender, RoutedEventArgs e)
        {
            using var enteredPassword = password.SecurePassword;
            submit.IsEnabled = !string.IsNullOrWhiteSpace(user.Text) && enteredPassword.Length > 0;
        }
        user.TextChanged += Update;
        password.PasswordChanged += Update;
        submit.Click += (_, _) => DialogResult = true;
        actions.Children.Add(cancel);
        actions.Children.Add(submit);
        form.Children.Add(actions);
        Content = form;
        Loaded += (_, _) => user.Focus();
    }
}
