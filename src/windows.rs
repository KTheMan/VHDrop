//! Blocking Windows backend. Run calls on a worker thread. Restart Manager is
//! advisory and may miss handles, especially in inaccessible or new paths.
use serde::Deserialize;
use std::{io::Write, process::Command};
#[derive(Debug, Clone, Deserialize)]
pub struct Disk {
    pub drive: String,
    pub image_path: String,
    pub partition: u32,
}
#[derive(Debug, Clone, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub started: u64,
}
#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    pub path: String,
    pub is_dir: bool,
}
fn ps(script: &str, vars: &[(&str, &str)]) -> Result<String, String> {
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoLogo","-NoProfile","-NonInteractive","-Command"])
  .arg(format!("[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $ErrorActionPreference='Stop'; {script}"));
    for (k, v) in vars {
        cmd.env(k, v);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let o = cmd.output().map_err(|e| format!("PowerShell: {e}"))?;
    if !o.status.success() {
        return Err(format!("{}", String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}
fn parse<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, String> {
    serde_json::from_str(s).map_err(|e| format!("Invalid Windows result: {e}"))
}
pub fn discover_disks() -> Result<Vec<Disk>, String> {
    let s = ps(
        r#"
$items=@(foreach($disk in @(Get-Disk)) { if($disk.Location -and $disk.Location -match '(?i)\.vhdx?$') {
 foreach($part in @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop)) { if($part.DriveLetter) {
  [pscustomobject]@{drive=($part.DriveLetter.ToString()+':\');image_path=[string]$disk.Location;partition=[int]$part.PartitionNumber}
 }} } })
ConvertTo-Json -InputObject $items -Compress
"#,
        &[],
    )?;
    parse(&s)
}
pub fn close_process(pid: u32, started: u64, force: bool) -> Result<String, String> {
    let pid = pid.to_string();
    let started = started.to_string();
    let force = if force { "1" } else { "0" };
    let script = format!(
        "{}\nAdd-Type -TypeDefinition @'\n{}\n'@\n{}",
        r#"
$p=Get-Process -Id ([int]$env:VHDX_PID) -ErrorAction Stop
if ([uint64]$p.StartTime.ToUniversalTime().ToFileTimeUtc() -ne [uint64]$env:VHDX_STARTED) {throw 'Process identity changed. Refresh before acting.'}
if($env:VHDX_FORCE -eq '1') {Stop-Process -Id $p.Id -ErrorAction Stop; 'Termination requested.'; exit}
"#,
        include_str!("close.cs"),
        r#"
$n=[WindowClose]::Request([uint32]$p.Id)
if($n -eq 0){throw 'No top-level windows found; this process may require its own shutdown method.'}
"Sent close requests to $n window(s). The application may prompt to save or refuse."
"#
    );
    ps(
        &script,
        &[
            ("VHDX_PID", &pid),
            ("VHDX_STARTED", &started),
            ("VHDX_FORCE", force),
        ],
    )
}
/// The only GUI detach path. Resolve a mapped drive in the unelevated user
/// session before requesting elevation, since UAC sessions may not see mappings.
pub fn detach(image_path: &str) -> Result<String, String> {
    let canonical = crate::delete_job::final_path(image_path)?;
    elevated_image_operation(&canonical, false)
}

/// Encode the path separately as UTF-16LE/base64 so no filename characters
/// can become PowerShell syntax, including smart quotes and newlines.
fn image_operation_script(image: &str, mount: bool) -> Result<String, String> {
    if image.is_empty() || image.contains('\0') || image.len() > 16000 {
        return Err("Invalid or overly long disk image path".into());
    }
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut path_bytes = Vec::with_capacity(image.len() * 2);
    for c in image.encode_utf16() { path_bytes.extend_from_slice(&c.to_le_bytes()); }
    let encoded = STANDARD.encode(path_bytes);
    let action = if mount { "Mount-DiskImage" } else { "Dismount-DiskImage" };
    let expected = if mount { "$true" } else { "$false" };
    let desired = if mount { "$false" } else { "$true" };
    Ok(format!(r#"$ErrorActionPreference='Stop'
try {{
 $path=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}'))
 $image=Get-DiskImage -ImagePath $path -ErrorAction Stop
 if ($image.Attached -eq {desired}) {{ {action} -ImagePath $path -ErrorAction Stop | Out-Null }}
 if ((Get-DiskImage -ImagePath $path -ErrorAction Stop).Attached -ne {expected}) {{ exit 31 }}
 exit 0
}} catch {{ exit 30 }}"#))
}

#[cfg(windows)]
pub(crate) fn elevated_image_operation(image: &str, mount: bool) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use std::{ffi::{c_void, OsStr}, os::windows::ffi::OsStrExt, ptr};
    #[repr(C)]
    struct ShellExecuteInfo {
        size:u32, mask:u32, hwnd:*mut c_void, verb:*const u16, file:*const u16,
        parameters:*const u16, directory:*const u16, show:i32, instance:*mut c_void,
        id_list:*mut c_void, class:*const u16, class_key:*mut c_void, hot_key:u32,
        icon:*mut c_void, process:*mut c_void,
    }
    #[link(name="shell32")]
    unsafe extern "system" { fn ShellExecuteExW(info:*mut ShellExecuteInfo)->i32; }
    #[link(name="kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer:*mut u16,size:u32)->u32;
        fn WaitForSingleObject(handle:*mut c_void, millis:u32)->u32;
        fn GetExitCodeProcess(handle:*mut c_void, code:*mut u32)->i32;
        fn CloseHandle(handle:*mut c_void)->i32;
    }
    fn wide(value: &OsStr)->Vec<u16> { value.encode_wide().chain(Some(0)).collect() }
    let script = image_operation_script(image, mount)?;
    let mut bytes=Vec::with_capacity(script.len()*2);
    for ch in script.encode_utf16() { bytes.extend_from_slice(&ch.to_le_bytes()); }
    let arguments=format!("-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {}",STANDARD.encode(bytes));
    if arguments.len() > 32760 { return Err("Disk image path is too long to pass safely to Windows elevation.".into()); }
    let mut system=vec![0u16;32768];
    let len=unsafe { GetSystemDirectoryW(system.as_mut_ptr(),system.len() as u32) } as usize;
    if len==0 || len>=system.len() { return Err(format!("Cannot locate Windows PowerShell: {}",std::io::Error::last_os_error())); }
    let system=String::from_utf16(&system[..len]).map_err(|_|"Invalid system directory")?;
    let ps=std::path::Path::new(&system).join(r"WindowsPowerShell\v1.0\powershell.exe");
    let file=wide(ps.as_os_str()); let verb=wide(OsStr::new("runas")); let args=wide(OsStr::new(&arguments));
    let mut info=ShellExecuteInfo {size:std::mem::size_of::<ShellExecuteInfo>() as u32,mask:0x40,hwnd:ptr::null_mut(),verb:verb.as_ptr(),file:file.as_ptr(),parameters:args.as_ptr(),directory:ptr::null(),show:0,instance:ptr::null_mut(),id_list:ptr::null_mut(),class:ptr::null(),class_key:ptr::null_mut(),hot_key:0,icon:ptr::null_mut(),process:ptr::null_mut()};
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let error=std::io::Error::last_os_error();
        return if error.raw_os_error()==Some(1223) { Err("Elevation was cancelled; the image was not changed by this request.".into()) } else { Err(format!("Could not request Windows elevation: {error}")) };
    }
    if info.process.is_null() { return Err("Windows did not provide an operation handle; check the image state before retrying.".into()); }
    let wait=unsafe { WaitForSingleObject(info.process,120_000) };
    let mut exit=0u32;
    let have_exit=wait==0 && unsafe { GetExitCodeProcess(info.process,&mut exit) }!=0;
    unsafe { CloseHandle(info.process); }
    if wait==258 { return Err("The elevated operation is still running. Check the image state before retrying.".into()); }
    if !have_exit { return Err("Could not determine the elevated operation result. Check the image state before retrying.".into()); }
    if exit!=0 { return Err(format!("Windows could not {} the image (operation code {exit}). Check the path, permissions and Windows Disk Management; a network share may be unavailable to the elevated session.",if mount {"attach"} else {"detach"})); }
    Ok(if mount {"Attached. Windows may take a moment to assign a drive letter."} else {"Disk image detached."}.into())
}

#[cfg(not(windows))]
pub(crate) fn elevated_image_operation(_image: &str, _mount: bool) -> Result<String, String> {
    Err("Windows disk operations are unavailable on this system.".into())
}

/// Check the exact image, including attachments without a mounted drive letter.
pub fn image_attached(image_path: &str) -> Result<bool, String> {
    let output = ps(
        r#"
$image=Get-DiskImage -ImagePath $env:VHDX_IMAGE -ErrorAction Stop
if($image.Attached) {'true'} else {'false'}
"#,
        &[("VHDX_IMAGE", image_path)],
    )?;
    match output.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("Unexpected disk image state: {output}")),
    }
}

/// One immediately visible directory. This does not recurse, count descendants,
/// or open files. Reparse points and inaccessible entries are omitted and counted.
#[derive(Debug, Clone)]
pub struct DirectoryListing {
    pub entries: Vec<Entry>,
    pub skipped: u64,
}

/// A deliberately bounded, partial hint about programs using visible files.
/// This cannot establish that a volume is free: unopened directories, directory
/// handles, protected processes, mapped sections and newly opened files can be missed.
#[derive(Debug, Clone, Deserialize)]
pub struct VisibleScan {
    pub processes: Vec<ProcessInfo>,
    pub skipped: u64,
    pub scan_errors: u64,
    pub inaccessible_processes: u64,
    pub files_considered: u64,
}

fn relative_parts(path: &str) -> Result<Vec<std::ffi::OsString>, String> {
    use std::path::{Component, Path};
    if path.contains(':') || path.contains('\n') || path.contains('\r') {
        return Err("Invalid relative path".into());
    }
    let mut parts = Vec::new();
    for part in Path::new(path).components() {
        match part {
            Component::Normal(name) => parts.push(name.to_os_string()),
            _ => return Err("Only paths inside the selected drive are allowed".into()),
        }
    }
    Ok(parts)
}

#[cfg(windows)]
fn is_reparse(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}
#[cfg(not(windows))]
fn is_reparse(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// List only the immediate children of `relative` under `root`, without
/// traversing reparse points. Run on a worker; disconnected drives may stall.
pub fn list_directory(root: &str, relative: &str) -> Result<DirectoryListing, String> {
    use std::path::PathBuf;
    let mut directory = PathBuf::from(root);
    if !directory.is_dir() {
        return Err(format!("Drive is not available: {root}"));
    }
    let parts = relative_parts(relative)?;
    let mut rel = PathBuf::new();
    for part in parts {
        directory.push(&part);
        rel.push(&part);
        let meta = std::fs::symlink_metadata(&directory)
            .map_err(|e| format!("Cannot inspect {}: {e}", directory.display()))?;
        if is_reparse(&meta) || !meta.is_dir() {
            return Err(format!("Not a regular directory: {}", directory.display()));
        }
    }
    let reader = std::fs::read_dir(&directory)
        .map_err(|e| format!("Cannot open {}: {e}", directory.display()))?;
    let mut result = DirectoryListing {
        entries: Vec::new(),
        skipped: 0,
    };
    for item in reader {
        let item = match item {
            Ok(v) => v,
            Err(_) => {
                result.skipped += 1;
                continue;
            }
        };
        let metadata = match std::fs::symlink_metadata(item.path()) {
            Ok(v) => v,
            Err(_) => {
                result.skipped += 1;
                continue;
            }
        };
        if is_reparse(&metadata) || !(metadata.is_file() || metadata.is_dir()) {
            result.skipped += 1;
            continue;
        }
        let name = item.file_name();
        if name.to_str().is_none() {
            result.skipped += 1;
            continue;
        }
        let relative_path = rel.join(name);
        if let Some(path) = relative_path.to_str() {
            result.entries.push(Entry {
                path: path.to_owned(),
                is_dir: metadata.is_dir(),
            });
        } else {
            result.skipped += 1;
        }
    }
    result.entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.path.to_lowercase().cmp(&b.path.to_lowercase()))
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(result)
}

/// Check at most 256 already-discovered regular files with Restart Manager and
/// add visible executables launched from this volume. This is advisory only.
/// It does not recursively enumerate the disk and will miss other open handles.
pub fn scan_visible_processes(root: &str, entries: &[Entry]) -> Result<VisibleScan, String> {
    const MAX_FILES: usize = 256;
    let mut candidates = Vec::new();
    let mut omitted = 0_u64;
    for e in entries.iter().filter(|e| !e.is_dir) {
        relative_parts(&e.path)?;
        if candidates.len() < MAX_FILES {
            candidates.push(&e.path);
        } else {
            omitted += 1;
        }
    }
    let mut tmp = None;
    for n in 0..20 {
        let path = std::env::temp_dir().join(format!(
            "vhdx-visible-{}-{n}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        if let Ok(f) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            tmp = Some((path, f));
            break;
        }
    }
    let (path, mut file) = tmp.ok_or("Could not create temporary process scan input")?;
    let result = (|| -> Result<VisibleScan, String> {
        for candidate in candidates {
            writeln!(file, "{candidate}").map_err(|e| e.to_string())?;
        }
        file.flush().map_err(|e| e.to_string())?;
        drop(file);
        let code=format!("Add-Type -TypeDefinition @'\n{}\n'@\n$r=[VisibleProcessScanner]::Scan($env:VHDX_ROOT,$env:VHDX_LIST,[long]$env:VHDX_OMITTED); ConvertTo-Json -InputObject $r -Depth 6 -Compress",include_str!("visible_scan.cs"));
        let filename = path.to_string_lossy();
        let omitted = omitted.to_string();
        let output = ps(
            &code,
            &[
                ("VHDX_ROOT", root),
                ("VHDX_LIST", &filename),
                ("VHDX_OMITTED", &omitted),
            ],
        )?;
        parse(&output)
    })();
    let _ = std::fs::remove_file(path);
    result
}

#[cfg(test)]
mod lazy_tests {
    use super::*;
    #[test]
    fn immediate_listing_does_not_walk_children_and_rejects_escape() {
        let base = std::env::temp_dir().join(format!(
            "vhdx-list-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(base.join("nested")).unwrap();
        std::fs::write(base.join("first.txt"), b"a").unwrap();
        std::fs::write(base.join("nested").join("hidden-until-opened.txt"), b"b").unwrap();
        let root = base.to_str().unwrap();
        let first = list_directory(root, "").unwrap();
        assert_eq!(first.entries.len(), 2);
        assert!(first.entries[0].is_dir);
        assert!(!first
            .entries
            .iter()
            .any(|e| e.path.contains("hidden-until-opened")));
        let next = list_directory(root, "nested").unwrap();
        assert_eq!(next.entries.len(), 1);
        assert!(next.entries[0].path.ends_with("hidden-until-opened.txt"));
        assert!(list_directory(root, "..\\outside").is_err());
        assert!(list_directory(root, "C:\\outside").is_err());
        std::fs::remove_dir_all(base).unwrap();
    }
    #[cfg(windows)]
    #[test]
    fn visible_scan_is_bounded_and_finds_a_locked_visible_file() {
        use std::io::{BufRead, BufReader};
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        let base = std::env::temp_dir().join(format!(
            "vhdx-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let locked = base.join("!locked.txt");
        std::fs::write(&locked, b"fixture").unwrap();
        for i in 0..300 {
            std::fs::write(base.join(format!("file{i:03}.txt")), b"x").unwrap();
        }
        let mut child=Command::new("powershell.exe").creation_flags(0x08000000)
            .args(["-NoProfile","-NonInteractive","-Command","$f=[IO.File]::Open($env:LOCK_FILE,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None); Write-Output READY; Start-Sleep -Seconds 60; $f.Dispose()"])
            .env("LOCK_FILE",&locked).stdout(Stdio::piped()).spawn().unwrap();
        let pid = child.id();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "READY");
        let listing = list_directory(base.to_str().unwrap(), "").unwrap();
        let result = scan_visible_processes(base.to_str().unwrap(), &listing.entries);
        let _ = child.kill();
        let _ = child.wait();
        let result = result.unwrap();
        assert_eq!(result.files_considered, 256);
        assert_eq!(result.skipped, 45);
        assert_eq!(result.scan_errors, 0);
        assert!(
            result.processes.iter().any(|p| p.pid == pid),
            "locked-file process missing: {:?}",
            result.processes
        );
        std::fs::remove_dir_all(base).unwrap();
    }
}

#[cfg(test)]
mod elevation_tests {
    use super::*;
    #[test]
    fn script_quotes_path_and_uses_fixed_operation() {
        let path = "\\\\server\\share\\O'Brien `$(bad).vhdx";
        let mount = image_operation_script(path, true).unwrap();
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let path_bytes: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(mount.contains(&STANDARD.encode(path_bytes)));
        assert!(!mount.contains("O'Brien"));
        assert!(mount.contains("Mount-DiskImage -ImagePath $path"));
        let detach = image_operation_script(path, false).unwrap();
        assert!(detach.contains("Dismount-DiskImage -ImagePath $path"));
        assert!(image_operation_script("a\0b.vhdx", true).is_err());
    }
    #[test]
    fn unicode_quotes_and_shell_metacharacters_are_only_base64_data() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let image = concat!(r#"C:\images\‘x’' ; $(Invoke-Expression evil) `".vhdx"#, "\nnext");
        let script = image_operation_script(image, true).unwrap();
        let prefix = "FromBase64String('";
        let encoded = script.split_once(prefix).unwrap().1.split_once("')").unwrap().0;
        let bytes = STANDARD.decode(encoded).unwrap();
        let units: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0],b[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap(), image);
        assert!(!script.contains("Invoke-Expression"));
        assert!(!script.contains('‘') && !script.contains('’'));
    }
}
