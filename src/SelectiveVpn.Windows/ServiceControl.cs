using System.ServiceProcess;
using SelectiveVpn.Core;

namespace SelectiveVpn.Windows;

public static class ServiceControl
{
    public static Task StopAsync() => Task.Run(() =>
    {
        using var service = new ServiceController(Wire.ServiceName);
        if (service.Status != ServiceControllerStatus.Stopped)
        {
            if (service.Status != ServiceControllerStatus.StopPending) service.Stop();
            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(45));
        }
    });
    public static Task StartAsync() => Task.Run(() =>
    {
        using var service = new ServiceController(Wire.ServiceName);
        if (service.Status != ServiceControllerStatus.Running)
        {
            if (service.Status != ServiceControllerStatus.StartPending) service.Start();
            service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
        }
    });
}
