using System.ComponentModel;
using System.Runtime.InteropServices;
using SelectiveVpn.Core;
using static SelectiveVpn.Windows.WfpNative;

namespace SelectiveVpn.Windows;

/// <summary>Persistent blocks outlive the service. Only dynamic TUN permits disappear on process death.</summary>
public sealed class WfpGuard : IDisposable
{
    private static readonly Guid ProviderKey = new("71f5315c-cd35-475c-8e0a-c4eba86f6641");
    private static readonly Guid SublayerKey = new("4ae32466-958a-4db6-b273-3d18eaf07afb");
    private static readonly Guid AppKey = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    private static readonly Guid InterfaceKey = new("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
    private static readonly Guid[] Layers = [new("c38d57d1-05a7-4c33-904f-7fbceee60e82"), new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"), new("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), new("a3b42c97-9f04-4672-b87e-cee9c483257f")];
    private IntPtr persistent;
    private IntPtr permits;
    private string[] protectedPaths = [];
    public bool Active { get; private set; }
    public int FilterCount => OwnFilters(persistent).Count;

    public WfpGuard()
    {
        if (Marshal.SizeOf<Filter>() != 200 || Marshal.SizeOf<Condition>() != 40)
            throw new PlatformNotSupportedException("WFP interop requires Windows x64.");
        persistent = Open(false);
        try
        {
            var provider = new Provider { Key = ProviderKey, Display = new() { Name = "SelectiveVpn" }, Flags = 1 };
            CheckExists(FwpmProviderAdd0(persistent, ref provider, IntPtr.Zero));
            // Upgrade an empty sublayer left by a previous build. Never remove active protection.
            if (OwnFilters(persistent).Count == 0)
            {
                var key = SublayerKey;
                uint removed = FwpmSubLayerDeleteByKey0(persistent, ref key);
                if (removed != 0x80320007) Check(removed);
            }
            WithGuid(ProviderKey, p =>
            {
                var sublayer = new Sublayer { Key = SublayerKey, Display = new() { Name = "SelectiveVpn application protection" }, Flags = 1, ProviderKey = p, Weight = ushort.MaxValue };
                CheckExists(FwpmSubLayerAdd0(persistent, ref sublayer, IntPtr.Zero));
            });
        }
        catch { Dispose(); throw; }
    }

    public void ReplaceProtectedApplications(IEnumerable<string> paths)
    {
        var next = paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (Active && protectedPaths.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(next)) return;
        CloseTunnel();
        Check(FwpmTransactionBegin0(persistent, 0));
        try
        {
            foreach (var id in OwnFilters(persistent)) Check(FwpmFilterDeleteById0(persistent, id));
            foreach (var path in next)
                foreach (var layer in Layers)
                {
                    Add(persistent, path, layer, 1, false, null);
                    // Boot filters cover the interval before persistent BFE policy is restored.
                    Add(persistent, path, layer, 2, false, null);
                }
            Check(FwpmTransactionCommit0(persistent));
            protectedPaths = next;
            Active = true;
        }
        catch { FwpmTransactionAbort0(persistent); throw; }
    }

    public void OpenTunnel(string alias)
    {
        CloseTunnel();
        Check(ConvertInterfaceAliasToLuid(alias, out var luid));
        if (luid == 0) throw new InvalidOperationException("TUN interface is missing.");
        permits = Open(true);
        try
        {
            Check(FwpmTransactionBegin0(permits, 0));
            foreach (var path in protectedPaths)
                foreach (var layer in Layers) Add(permits, path, layer, 0, true, luid);
            Check(FwpmTransactionCommit0(permits));
        }
        catch { CloseTunnel(); throw; }
    }

    public void CloseTunnel()
    {
        if (permits == IntPtr.Zero) return;
        var h = permits;
        Check(FwpmEngineClose0(h));
        permits = IntPtr.Zero;
    }

    public static void RemoveProtection()
    {
        using var guard = new WfpGuard();
        guard.ReplaceProtectedApplications([]);
    }

    private static void Add(IntPtr engine, string path, Guid layer, uint flags, bool permit, ulong? luid)
    {
        // FwpmGetAppIdFromFileName0 lowercases ASCII only on this Windows build.
        // ALE's image path is Unicode-lowercase (e.g. Cyrillic folder names).
        Check(FwpmGetAppIdFromFileName0(path.ToLowerInvariant(), out var appId));
        IntPtr conditions = IntPtr.Zero, interfaceValue = IntPtr.Zero;
        try
        {
            var appBlob = Marshal.PtrToStructure<Blob>(appId);
            var appText = Marshal.PtrToStringUni(appBlob.Data, checked((int)appBlob.Size / 2))!.ToLowerInvariant();
            var appBytes = System.Text.Encoding.Unicode.GetBytes(appText);
            if (appBytes.Length != appBlob.Size) throw new InvalidDataException("Unexpected WFP application ID encoding.");
            Marshal.Copy(appBytes, 0, appBlob.Data, appBytes.Length);
            var list = new List<Condition> { new() { Key = AppKey, Match = 0, Value = new() { Type = 12, Pointer = appId } } };
            if (luid.HasValue)
            {
                interfaceValue = Marshal.AllocHGlobal(8);
                Marshal.WriteInt64(interfaceValue, unchecked((long)luid.Value));
                list.Add(new() { Key = InterfaceKey, Match = 0, Value = new() { Type = 4, Pointer = interfaceValue } });
            }
            int size = Marshal.SizeOf<Condition>();
            conditions = Marshal.AllocHGlobal(size * list.Count);
            for (int i = 0; i < list.Count; i++) Marshal.StructureToPtr(list[i], conditions + i * size, false);
            WithGuid(ProviderKey, provider =>
            {
                var filter = new Filter
                {
                    Key = Guid.NewGuid(), Display = new() { Name = permit ? "SelectiveVpn TUN permit" : "SelectiveVpn fail-closed block" },
                    Flags = flags, ProviderKey = provider, Layer = layer, Sublayer = SublayerKey,
                    Weight = new() { Type = 1, Number = permit ? 15UL : 1UL },
                    ConditionCount = (uint)list.Count, Conditions = conditions,
                    Action = new() { Type = permit ? 0x1002U : 0x1001U }
                };
                Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out _));
            });
        }
        finally
        {
            if (conditions != IntPtr.Zero) Marshal.FreeHGlobal(conditions);
            if (interfaceValue != IntPtr.Zero) Marshal.FreeHGlobal(interfaceValue);
            FwpmFreeMemory0(ref appId);
        }
    }

    private static List<ulong> OwnFilters(IntPtr engine)
    {
        var result = new List<ulong>();
        foreach (var layer in Layers) EnumerateLayer(engine, layer, result);
        return result;
    }

    private static void EnumerateLayer(IntPtr engine, Guid layer, List<ulong> result)
    {
        var template = new EnumTemplate { Layer = layer, Flags = 8 | 16, ActionMask = uint.MaxValue };
        var templatePtr = Marshal.AllocHGlobal(Marshal.SizeOf<EnumTemplate>());
        IntPtr iterator;
        try
        {
            Marshal.StructureToPtr(template, templatePtr, false);
            Check(FwpmFilterCreateEnumHandle0(engine, templatePtr, out iterator));
        }
        finally { Marshal.FreeHGlobal(templatePtr); }
        try
        {
            uint count;
            do
            {
                Check(FwpmFilterEnum0(engine, iterator, 256, out var entries, out count));
                try
                {
                    for (int i = 0; i < count; i++)
                    {
                        var f = Marshal.PtrToStructure<Filter>(Marshal.ReadIntPtr(entries, i * IntPtr.Size));
                        if (f.Sublayer == SublayerKey)
                        {
                            result.Add(f.Id);
                        }
                    }
                }
                finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
            } while (count == 256);
        }
        finally { FwpmFilterDestroyEnumHandle0(engine, iterator); }
    }

    private static IntPtr Open(bool dynamic)
    {
        var session = new Session { Key = Guid.NewGuid(), Display = new() { Name = "SelectiveVpn" }, Flags = dynamic ? 1U : 0U, Timeout = 15000 };
        Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, ref session, out var engine));
        return engine;
    }
    private static void WithGuid(Guid value, System.Action<IntPtr> action)
    {
        var p = Marshal.AllocHGlobal(16);
        try { Marshal.StructureToPtr(value, p, false); action(p); }
        finally { Marshal.FreeHGlobal(p); }
    }
    private static void Check(uint code) { if (code != 0) throw new Win32Exception(unchecked((int)code), $"WFP error 0x{code:X8}"); }
    private static void CheckExists(uint code) { if (code != 0x80320009) Check(code); }
    public void Dispose()
    {
        CloseTunnel();
        if (persistent != IntPtr.Zero) { FwpmEngineClose0(persistent); persistent = IntPtr.Zero; }
    }
}
