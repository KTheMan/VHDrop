using System;
using System.Runtime.InteropServices;
public static class WindowClose {
 public delegate bool Callback(IntPtr h, IntPtr l);
 [DllImport("user32.dll")] static extern bool EnumWindows(Callback f, IntPtr l);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
 [DllImport("user32.dll")] static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
 public static int Request(uint pid) { int n=0; EnumWindows((h,l) => {uint p;GetWindowThreadProcessId(h,out p);if(p==pid && PostMessage(h,0x10,IntPtr.Zero,IntPtr.Zero))n++;return true;},IntPtr.Zero);return n; }
}
