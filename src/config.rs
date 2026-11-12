//! Per-user connection settings. Authentication stays in OpenSSH, never here.
use serde::{Deserialize, Serialize};
use std::{path::{Path, PathBuf}, io::Write};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub copy_ssh: String,
    pub share: String,
    pub guest_root: String,
    pub delete_ssh: String,
    pub host_root: String,
    pub delete_helper: String,
    pub guard_container_id: String,
    pub guard_guest_username: String,
    pub guard_guest_smb_acknowledged: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self { copy_ssh: String::new(), share: String::new(), guest_root: String::new(), delete_ssh: String::new(), host_root: String::new(), delete_helper: "/opt/vhdx-handoff-v1/vhdx_delete.py".into(), guard_container_id: String::new(), guard_guest_username: String::new(), guard_guest_smb_acknowledged: false }
    }
}
impl Config {
    fn path() -> Result<PathBuf, String> {
        Ok(PathBuf::from(std::env::var_os("APPDATA").ok_or("APPDATA is not available")?).join("VHDX Handoff").join("connections.json"))
    }
    pub fn load() -> Result<Option<Self>, String> {
        let p=Self::path()?;
        match std::fs::read(&p) {
            Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e|format!("Invalid settings in {}: {e}",p.display())),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Cannot read {}: {e}",p.display())),
        }
    }
    pub fn save(&self) -> Result<(), String> {
        let p=Self::path()?;
        std::fs::create_dir_all(p.parent().ok_or("Invalid settings path")?).map_err(|e|e.to_string())?;
        let bytes=serde_json::to_vec_pretty(self).map_err(|e|e.to_string())?;
        write_atomic(&p, &bytes)
    }
    pub fn copy_configured(&self)->bool { !self.copy_ssh.trim().is_empty() && !self.share.trim().is_empty() && !self.guest_root.trim().is_empty() }
    pub fn delete_configured(&self)->bool { self.copy_configured() && !self.delete_ssh.trim().is_empty() && !self.host_root.trim().is_empty() && !self.delete_helper.trim().is_empty() }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent=path.parent().ok_or("Invalid settings path")?;
    let stamp=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e|e.to_string())?.as_nanos();
    let tmp=parent.join(format!(".connections-{}-{stamp}.tmp",std::process::id()));
    let result=(|| {
        let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e|e.to_string())?;
        f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|e|e.to_string())?;
        drop(f);
        replace(&tmp,path)
    })();
    if result.is_err() { let _=std::fs::remove_file(&tmp); }
    result.map_err(|e|format!("Cannot save {}: {e}",path.display()))
}
#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> Result<(), String> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    #[link(name="kernel32")] unsafe extern "system" { fn MoveFileExW(from: *const u16, to: *const u16, flags: u32)->i32; }
    let a:Vec<u16>=OsStr::new(from).encode_wide().chain(Some(0)).collect();
    let b:Vec<u16>=OsStr::new(to).encode_wide().chain(Some(0)).collect();
    if unsafe{MoveFileExW(a.as_ptr(),b.as_ptr(),0x1 | 0x8)}==0 {Err(std::io::Error::last_os_error().to_string())} else {Ok(())}
}
#[cfg(not(windows))]
fn replace(from: &Path, to: &Path) -> Result<(), String> { std::fs::rename(from,to).map_err(|e|e.to_string()) }
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn defaults_have_no_hosts_and_roundtrip() {
        let config=Config::default(); assert!(!config.copy_configured()); assert!(!config.delete_configured());
        let json=serde_json::to_string(&config).unwrap(); assert_eq!(serde_json::from_str::<Config>(&json).unwrap(),config);
    }
    #[test] fn atomically_replace_settings_file() {
        let dir=std::env::temp_dir().join(format!("vhdx-handoff-config-test-{}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap(); let p=dir.join("connections.json");
        write_atomic(&p,b"old").unwrap(); write_atomic(&p,b"new").unwrap(); assert_eq!(std::fs::read(&p).unwrap(),b"new");
        std::fs::remove_file(&p).unwrap(); std::fs::remove_dir(&dir).unwrap();
    }
}
