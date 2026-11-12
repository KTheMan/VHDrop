using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class VisibleProcessInfo { public uint pid; public string name; public ulong started; }
public class VisibleProcessResult {
 public long skipped, scan_errors, inaccessible_processes, files_considered;
 public List<VisibleProcessInfo> processes = new List<VisibleProcessInfo>();
}
public static class VisibleProcessScanner {
 [StructLayout(LayoutKind.Sequential)] struct FT { public uint low; public uint high; }
 [StructLayout(LayoutKind.Sequential)] struct Unique { public uint pid; public FT start; }
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Info {
  public Unique process;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string name;
  [MarshalAs(UnmanagedType.ByValTStr, SizeConst=64)] public string service;
  public int appType; public uint status, sessionId;
  [MarshalAs(UnmanagedType.Bool)] public bool restartable;
 }
 [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] static extern int RmStartSession(out uint session, int flags, StringBuilder key);
 [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)] static extern int RmRegisterResources(uint session, uint files, string[] names, uint apps, IntPtr app, uint services, IntPtr service);
 [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint session, out uint needed, ref uint count, [In,Out] Info[] info, ref uint reasons);
 [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint session);
 static void Add(VisibleProcessResult result, HashSet<string> seen, uint pid, ulong started, string name) {
  if(seen.Add(pid+":"+started)) result.processes.Add(new VisibleProcessInfo{pid=pid, started=started, name=name});
 }
 public static VisibleProcessResult Scan(string root, string pathsFile, long omitted) {
  var result=new VisibleProcessResult(); result.skipped=omitted;
  var seen=new HashSet<string>();
  root=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;
  if(!Directory.Exists(root)) throw new DirectoryNotFoundException(root);
  var files=new List<string>();
  foreach(var relative in File.ReadLines(pathsFile,Encoding.UTF8)) {
   if(String.IsNullOrEmpty(relative) || Path.IsPathRooted(relative) || relative.Contains(":")) {result.skipped++;continue;}
   var pieces=relative.Split(new char[]{'\\','/'});
   bool bad=false;foreach(var piece in pieces) if(piece==".." || piece=="." || piece=="") bad=true;
   if(bad){result.skipped++;continue;}
   string path=Path.GetFullPath(Path.Combine(root,relative));
   if(!path.StartsWith(root,StringComparison.OrdinalIgnoreCase)){result.skipped++;continue;}
   try {
    // Never register a directory: RmGetList reports access denied if any resource is a directory.
    var attrs=File.GetAttributes(path);
    if((attrs & (FileAttributes.Directory|FileAttributes.ReparsePoint))!=0){result.skipped++;continue;}
    files.Add(path);
   } catch { result.skipped++; }
  }
  result.files_considered=files.Count;
  if(files.Count>0){
   uint session; int code=RmStartSession(out session,0,new StringBuilder(33));
   if(code!=0) result.scan_errors+=files.Count;
   else try {
    code=RmRegisterResources(session,(uint)files.Count,files.ToArray(),0,IntPtr.Zero,0,IntPtr.Zero);
    if(code!=0) result.scan_errors+=files.Count;
    else {
     uint needed=0,count=0,reasons=0;code=RmGetList(session,out needed,ref count,null,ref reasons);
     if(code==234) {
      for(int retry=0;retry<3;retry++){
       count=needed;var infos=new Info[count];code=RmGetList(session,out needed,ref count,infos,ref reasons);
       if(code==234)continue;
       if(code==0)for(int i=0;i<count;i++){
        var p=infos[i].process;Add(result,seen,p.pid,((ulong)p.start.high<<32)|p.start.low,infos[i].name);
       }
       break;
      }
     }
     if(code!=0)result.scan_errors+=files.Count;
    }
   } finally { RmEndSession(session); }
  }
  // Executables on the disk are useful additional hints, even when their file is in an unopened directory.
  foreach(var process in Process.GetProcesses()) {
   try {
    var exe=process.MainModule.FileName;
    if(exe.StartsWith(root,StringComparison.OrdinalIgnoreCase))
     Add(result,seen,(uint)process.Id,(ulong)process.StartTime.ToUniversalTime().ToFileTimeUtc(),process.ProcessName);
   } catch { result.inaccessible_processes++; }
   finally { process.Dispose(); }
  }
  return result;
 }
}
