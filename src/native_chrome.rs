//! Keep the native Windows frame and accessible title while matching the
//! mockup's unlabelled caption area. Failure leaves the ordinary frame intact.

#[cfg(target_os = "windows")]
use raw_window_handle::{HasWindowHandle, RawWindowHandle};

#[cfg(target_os = "windows")]
#[repr(C)]
struct NonClientOptions {
    flags: u32,
    mask: u32,
}

#[cfg(target_os = "windows")]
#[link(name = "uxtheme")]
extern "system" {
    fn SetWindowThemeAttribute(
        hwnd: isize,
        attribute: i32,
        value: *const NonClientOptions,
        size: u32,
    ) -> i32;
}

/// Hide only the painted title and icon, without changing the actual window
/// text, frame styles, resize hit testing, system menu or caption controls.
/// Windows may ignore theme attributes; callers can safely retain its default.
#[cfg(target_os = "windows")]
pub fn simplify_caption(cc: &eframe::CreationContext<'_>) -> Result<(), String> {
    const WTA_NONCLIENT: i32 = 1;
    const WTNCA_NODRAWCAPTION: u32 = 1;
    const WTNCA_NODRAWICON: u32 = 2;
    let handle = cc.window_handle().map_err(|e| e.to_string())?;
    let RawWindowHandle::Win32(window) = handle.as_raw() else {
        return Err("Window handle is not Win32".into());
    };
    let attributes = WTNCA_NODRAWCAPTION | WTNCA_NODRAWICON;
    let options = NonClientOptions { flags: attributes, mask: attributes };
    // SAFETY: the creation context supplies a live Win32 HWND; options is a
    // correctly laid-out WTA_OPTIONS value for this synchronous system call.
    let result = unsafe {
        SetWindowThemeAttribute(
            window.hwnd.get(), WTA_NONCLIENT, &options,
            std::mem::size_of::<NonClientOptions>() as u32,
        )
    };
    if result < 0 { Err(format!("SetWindowThemeAttribute failed: {result:#x}")) } else { Ok(()) }
}

#[cfg(not(target_os = "windows"))]
pub fn simplify_caption(_: &eframe::CreationContext<'_>) -> Result<(), String> { Ok(()) }
