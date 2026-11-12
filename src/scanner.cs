using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public class StockEntry { public string path; public bool is_dir; }
public class StockProcess { public uint pid; public string name; public ulong started; }
public class StockResult {
 public long files, directories, bytes, skipped, scan_errors;
 public List<StockEntry> entries = new List<StockEntry>();
 public List<StockProcess> processes = new List<StockProcess>();
}
public static class VolumeInventory {
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
 static void Batch(List<string> paths, StockResult result, HashSet<string> seen) {
  if (paths.Count==0) return;
  uint h; if (RmStartSession(out h,0,new StringBuilder(33))!=0) {result.scan_errors+=paths.Count;return;}
  try {
   if (RmRegisterResources(h,(uint)paths.Count,paths.ToArray(),0,IntPtr.Zero,0,IntPtr.Zero)!=0) {result.scan_errors+=paths.Count;return;}
   uint needed=0,count=0,reasons=0; int code=RmGetList(h,out needed,ref count,null,ref reasons);
   if(code==0)return;
   if(code!=234){result.scan_errors+=paths.Count;return;}
   for(int retry=0;retry<3;retry++) {
    count=needed; var infos=new Info[count]; code=RmGetList(h,out needed,ref count,infos,ref reasons);
    if(code==234)continue;
    if(code!=0){result.scan_errors+=paths.Count;return;}
    for(int i=0;i<count;i++) {
     var p=infos[i].process; ulong start=((ulong)p.start.high<<32)|p.start.low;
     if(seen.Add(p.pid+":"+start)) result.processes.Add(new StockProcess{pid=p.pid,name=infos[i].name,started=start});
    }
    return;
   }
   result.scan_errors+=paths.Count;
  } finally {RmEndSession(h);}
 }
 public static StockResult Inspect(string root) {
  root=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;
  if(!Directory.Exists(root))throw new DirectoryNotFoundException(root);
  var result=new StockResult();var seen=new HashSet<string>();var todo=new Stack<string>();var batch=new List<string>(256);
  todo.Push(root);batch.Add(root);
  while(todo.Count>0){
   string dir=todo.Pop();
   try{foreach(string path in Directory.EnumerateFileSystemEntries(dir)){
    try{
     var attr=File.GetAttributes(path);if((attr&FileAttributes.ReparsePoint)!=0){result.skipped++;continue;}
     bool isdir=(attr&FileAttributes.Directory)!=0;
     result.entries.Add(new StockEntry{path=path.Substring(root.Length),is_dir=isdir});
     if(isdir){result.directories++;todo.Push(path);}else{result.files++;result.bytes+=new FileInfo(path).Length;}
     batch.Add(path);if(batch.Count>=256){Batch(batch,result,seen);batch.Clear();}
    }catch(Exception){result.skipped++;}
   }}catch(Exception){result.skipped++;}
  }
  Batch(batch,result,seen);return result;
 }
 public static StockResult Scan(string root, string json) {
  var result=new StockResult();var seen=new HashSet<string>();var batch=new List<string>(256);
  root=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;
  if(!Directory.Exists(root))throw new DirectoryNotFoundException(root);
  batch.Add(root);
  foreach(string path in File.ReadLines(json)){
   if(path.IndexOfAny(new char[]{'\r','\n'})>=0 || Path.IsPathRooted(path) || path.StartsWith("..\\") || path=="..") {result.skipped++;continue;}
   batch.Add(Path.Combine(root,path));if(batch.Count>=256){Batch(batch,result,seen);batch.Clear();}
  }
  Batch(batch,result,seen);return result;
 }
}
