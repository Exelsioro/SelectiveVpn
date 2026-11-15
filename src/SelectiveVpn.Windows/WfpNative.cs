using System.Runtime.InteropServices;

namespace SelectiveVpn.Windows;

internal static class WfpNative
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct Display { [MarshalAs(UnmanagedType.LPWStr)] public string? Name; [MarshalAs(UnmanagedType.LPWStr)] public string? Description; }
    [StructLayout(LayoutKind.Sequential)] internal struct Blob { public uint Size; public IntPtr Data; }
    [StructLayout(LayoutKind.Explicit, Size = 16)] internal struct Value
    { [FieldOffset(0)] public int Type; [FieldOffset(8)] public ulong Number; [FieldOffset(8)] public IntPtr Pointer; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct Session
    { public Guid Key; public Display Display; public uint Flags; public uint Timeout; public uint Pid; public IntPtr Sid; public IntPtr Username; public int Kernel; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct Provider
    { public Guid Key; public Display Display; public uint Flags; public Blob Data; [MarshalAs(UnmanagedType.LPWStr)] public string? ServiceName; }
    [StructLayout(LayoutKind.Sequential)] internal struct Sublayer
    { public Guid Key; public Display Display; public uint Flags; public IntPtr ProviderKey; public Blob Data; public ushort Weight; }
    [StructLayout(LayoutKind.Sequential)] internal struct Condition
    { public Guid Key; public int Match; public Value Value; }
    [StructLayout(LayoutKind.Sequential)] internal struct EnumTemplate
    { public IntPtr ProviderKey; public Guid Layer; public int Type; public uint Flags; public IntPtr Context; public uint Count; public IntPtr Conditions; public uint ActionMask; public IntPtr CalloutKey; }
    [StructLayout(LayoutKind.Sequential)] internal struct Action { public uint Type; public Guid Key; }
    [StructLayout(LayoutKind.Explicit, Size = 16)] internal struct Context
    { [FieldOffset(0)] public ulong Raw; [FieldOffset(0)] public Guid Key; }
    [StructLayout(LayoutKind.Sequential)] internal struct Filter
    {
        public Guid Key; public Display Display; public uint Flags; public IntPtr ProviderKey;
        public Blob Data; public Guid Layer; public Guid Sublayer; public Value Weight;
        public uint ConditionCount; public IntPtr Conditions; public Action Action; public Context Context;
        public IntPtr Reserved; public ulong Id; public Value EffectiveWeight;
    }
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] internal static extern uint FwpmEngineOpen0(string? server, uint auth, IntPtr authIdentity, ref Session session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmProviderAdd0(IntPtr engine, ref Provider provider, IntPtr sd);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer sublayer, IntPtr sd);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr sd, out ulong id);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterDeleteById0(IntPtr engine, ulong id);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr enumHandle);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr enumHandle, uint count, out IntPtr entries, out uint returned);
    [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumHandle);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] internal static extern uint FwpmGetAppIdFromFileName0(string path, out IntPtr appId);
    [DllImport("fwpuclnt.dll")] internal static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode)] internal static extern uint ConvertInterfaceAliasToLuid(string alias, out ulong luid);
}
