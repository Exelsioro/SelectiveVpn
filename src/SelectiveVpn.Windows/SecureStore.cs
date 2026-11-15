using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using SelectiveVpn.Core;

namespace SelectiveVpn.Windows;

public sealed class SecureStore
{
    public string Root { get; }
    public SecureStore(string? root = null)
    {
        Root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SelectiveVpn");
        Directory.CreateDirectory(Root);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            security.AddAccessRule(new(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(Root).SetAccessControl(security);
    }
    public ClientSettings LoadSettings() => File.Exists(Path.Combine(Root, "settings.json"))
        ? Policy.Normalize(JsonSerializer.Deserialize<ClientSettings>(File.ReadAllText(Path.Combine(Root, "settings.json")), Wire.Json) ?? throw new InvalidDataException("Empty settings."))
        : new();
    public void SaveSettings(ClientSettings settings) => Write("settings.json", JsonSerializer.SerializeToUtf8Bytes(settings, Wire.Json));
    public ServerProfile[] LoadServers()
    {
        var path = Path.Combine(Root, "servers.dpapi");
        if (!File.Exists(path)) return [];
        var plaintext = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.LocalMachine);
        try { return JsonSerializer.Deserialize<ServerProfile[]>(plaintext, Wire.Json) ?? []; }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }
    public void SaveServers(ServerProfile[] servers)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(servers, Wire.Json);
        try { Write("servers.dpapi", ProtectedData.Protect(plaintext, null, DataProtectionScope.LocalMachine)); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }
    public void Write(string name, byte[] data)
    {
        string target = Path.Combine(Root, name), temp = target + ".new";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { stream.Write(data); stream.Flush(true); }
        File.Move(temp, target, true);
    }
}
