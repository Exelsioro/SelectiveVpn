# Bounded framed RPC with the same installed-image check as the application UI.
if (-not ('SelectiveAcceptanceRpc' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
public static class SelectiveAcceptanceRpc {
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
 static void Wait(Task task, Stopwatch watch, int timeout) {
   int left = timeout - (int)watch.ElapsedMilliseconds;
   if (left <= 0 || !task.Wait(left)) throw new TimeoutException("VPN control request timed out");
   task.GetAwaiter().GetResult();
 }
 static byte[] Read(Stream stream, int size, Stopwatch watch, int timeout) {
   byte[] data = new byte[size]; int offset=0;
   while(offset<size) {
     Task<int> task=stream.ReadAsync(data,offset,size-offset);
     Wait(task,watch,timeout); int count=task.GetAwaiter().GetResult();
     if(count==0) throw new EndOfStreamException(); offset+=count;
   }
   return data;
 }
 public static string Call(string json, string expected, int timeout) {
   using(var pipe=new NamedPipeClientStream(".","SelectiveVpn.Control.v1",PipeDirection.InOut,PipeOptions.Asynchronous)) {
     pipe.Connect(2500); uint pid;
     if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid)) throw new IOException("Cannot identify RPC server");
     using(var process=Process.GetProcessById((int)pid))
       if(!String.Equals(process.MainModule.FileName,expected,StringComparison.OrdinalIgnoreCase))
         throw new UnauthorizedAccessException("Unexpected VPN service image");
     var watch=Stopwatch.StartNew(); byte[] bytes=Encoding.UTF8.GetBytes(json);
     Wait(pipe.WriteAsync(BitConverter.GetBytes(bytes.Length),0,4),watch,timeout);
     Wait(pipe.WriteAsync(bytes,0,bytes.Length),watch,timeout);
     int size=BitConverter.ToInt32(Read(pipe,4,watch,timeout),0);
     if(size<1 || size>5*1024*1024) throw new InvalidDataException("Invalid frame");
     return Encoding.UTF8.GetString(Read(pipe,size,watch,timeout));
   }
 }
}
'@
}
