//! Per-user VHDX history and explicitly requested Windows disk-image mounting.
//! All public functions are blocking; call them on a worker thread.
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

const LIMIT: usize = 12;
static HISTORY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn history_path() -> Result<PathBuf, String> {
    let local = std::env::var_os("LOCALAPPDATA")
        .ok_or("LOCALAPPDATA is not set; recent images are unavailable")?;
    Ok(PathBuf::from(local)
        .join("VHDX Handoff")
        .join("recent-images.json"))
}

/// Accept only fully qualified disk-image filenames; pass strings as environment values,
/// never as PowerShell code. Validation does not attach or even open an image.
fn validate_image(path: &str) -> Result<(), String> {
    if path.is_empty() || path.contains('\0') || path.len() > 32760 {
        return Err("Invalid disk image path".into());
    }
    let candidate = Path::new(path);
    if !candidate.is_absolute() {
        return Err("Choose a fully qualified local or network VHDX path".into());
    }
    let ext = candidate.extension().and_then(|s| s.to_str()).unwrap_or("");
    if !ext.eq_ignore_ascii_case("vhdx") && !ext.eq_ignore_ascii_case("vhd") {
        return Err("Choose a .vhdx or .vhd disk image".into());
    }
    Ok(())
}

fn read_from(path: &Path) -> Result<Vec<String>, String> {
    match fs::read(path) {
        Ok(bytes) => {
            let list: Vec<String> = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Recent image list is invalid ({}): {e}", path.display()))?;
            // Treat a damaged or hand-edited file as data, never as executable code.
            Ok(list
                .into_iter()
                .filter(|p| validate_image(p).is_ok())
                .take(LIMIT)
                .collect())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!(
            "Could not read recent images ({}): {e}",
            path.display()
        )),
    }
}

fn write_to(path: &Path, entries: &[String]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or("Recent image list has no parent folder")?;
    fs::create_dir_all(parent).map_err(|e| format!("Could not create recent image folder: {e}"))?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut last_error = None;
    for attempt in 0..32 {
        let tmp = parent.join(format!(
            ".recent-images-{}-{stamp}-{attempt}.tmp",
            std::process::id()
        ));
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(mut file) => {
                let result = (|| -> Result<(), String> {
                    let bytes = serde_json::to_vec_pretty(entries).map_err(|e| e.to_string())?;
                    file.write_all(&bytes)
                        .map_err(|e| format!("Could not write recent images: {e}"))?;
                    file.sync_all()
                        .map_err(|e| format!("Could not save recent images: {e}"))?;
                    drop(file);
                    fs::rename(&tmp, path)
                        .map_err(|e| format!("Could not replace recent image list: {e}"))?;
                    Ok(())
                })();
                if result.is_err() {
                    let _ = fs::remove_file(&tmp);
                }
                return result;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_error = Some(e),
            Err(e) => return Err(format!("Could not create temporary recent image list: {e}")),
        }
    }
    Err(format!(
        "Could not create unique recent image list: {}",
        last_error.map(|e| e.to_string()).unwrap_or_default()
    ))
}

fn remember_at(path: &Path, image: &str) -> Result<Vec<String>, String> {
    validate_image(image)?;
    let mut list = read_from(path)?;
    list.retain(|existing| !existing.eq_ignore_ascii_case(image));
    list.insert(0, image.to_owned());
    list.truncate(LIMIT);
    write_to(path, &list)?;
    Ok(list)
}

/// Load images previously selected or mounted in this app, newest first.
/// An empty list means no app history; this does not represent all Windows history.
pub fn load() -> Result<Vec<String>, String> {
    let _guard = HISTORY_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "Could not lock recent image list")?;
    read_from(&history_path()?)
}

/// Remember a selected/observed absolute image path, keeping newest first.
pub fn remember(image: &str) -> Result<Vec<String>, String> {
    let _guard = HISTORY_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "Could not lock recent image list")?;
    remember_at(&history_path()?, image)
}

/// Explicitly mount a VHD/VHDX with Windows. Does not force close processes or detach.
/// A successful mount is recorded; a history failure is returned as a success warning,
/// because the image may already be attached and must not be presented as a failed mount.
pub fn mount(image: &str) -> Result<String, String> {
    validate_image(image)?;
    // Resolve mapped drives to their stable UNC view before elevation and use
    // that very same path for both the guard check and the Windows operation.
    let canonical = crate::delete_job::final_path(image)?;
    crate::delete_job::check_before_mount(&canonical)?;
    let message = crate::windows::elevated_image_operation(&canonical, true)?;
    match remember(image) {
        Ok(_) => Ok(message),
        Err(e) => Ok(format!(
            "{message} Recent-image history could not be saved: {e}"
        )),
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn history_deduplicates_limits_and_remains_isolated() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("vhdx-history-test-{}-{stamp}", std::process::id()));
        let history = root.join("nested").join("recent-images.json");
        assert!(read_from(&history).unwrap().is_empty());
        assert!(remember_at(&history, "relative.vhdx").is_err());
        assert!(remember_at(&history, r"C:\images\not-an-image.txt").is_err());
        for n in 0..14 {
            remember_at(&history, &format!(r"C:\images\disk{n}.vhdx")).unwrap();
        }
        let list = remember_at(&history, r"c:\IMAGES\DISK8.VHDX").unwrap();
        assert_eq!(list.len(), LIMIT);
        assert_eq!(list[0], r"c:\IMAGES\DISK8.VHDX");
        assert_eq!(
            list.iter()
                .filter(|s| s.eq_ignore_ascii_case(r"C:\images\disk8.vhdx"))
                .count(),
            1
        );
        assert_eq!(read_from(&history).unwrap(), list);
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn absolute_unc_and_uppercase_extension_are_accepted() {
        assert!(validate_image(r"\\server\share\ExampleDisk.VHDX").is_ok());
        assert!(validate_image(r"C:\images\ordinary.vhd").is_ok());
        assert!(validate_image(r"C:relative.vhdx").is_err());
        assert!(validate_image("C:\\images\\bad.vhdx\0tail").is_err());
    }
    #[test]
    fn malformed_history_is_not_overwritten() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("vhdx-bad-history-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let history = root.join("recent.json");
        fs::write(&history, b"not json").unwrap();
        assert!(remember_at(&history, r"C:\images\new.vhdx").is_err());
        assert_eq!(fs::read(&history).unwrap(), b"not json");
        let _ = fs::remove_dir_all(root);
    }
}
