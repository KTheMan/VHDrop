//! Per-user theme preference and the Windows app color-mode setting.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    Light,
    Dark,
    #[default]
    System,
}
impl ThemeMode {
    pub fn light(self, system_light: bool) -> bool {
        match self {
            Self::Light => true,
            Self::Dark => false,
            Self::System => system_light,
        }
    }
}
fn path() -> Option<PathBuf> {
    Some(
        PathBuf::from(std::env::var_os("APPDATA")?)
            .join("VHDX Handoff")
            .join("theme.json"),
    )
}
pub fn load() -> ThemeMode {
    path()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}
pub fn save(mode: ThemeMode) -> Result<(), String> {
    let p = path().ok_or("APPDATA is not available")?;
    std::fs::create_dir_all(p.parent().ok_or("Invalid theme path")?).map_err(|e| e.to_string())?;
    std::fs::write(&p, serde_json::to_vec(&mode).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}
/// Query the documented Windows per-user app theme without modifying it.
pub fn system_light() -> Option<bool> {
    let mut cmd = std::process::Command::new("reg.exe");
    cmd.args([
        "query",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        "/v",
        "AppsUseLightTheme",
    ]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("AppsUseLightTheme"))?;
    let value = line.split_whitespace().last()?;
    match value.to_ascii_lowercase().as_str() {
        "0x0" => Some(false),
        "0x1" => Some(true),
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_and_default() {
        assert_eq!(ThemeMode::default(), ThemeMode::System);
        assert!(ThemeMode::System.light(true));
        assert!(!ThemeMode::System.light(false));
        assert!(ThemeMode::Light.light(false));
        assert!(!ThemeMode::Dark.light(true));
    }
}
