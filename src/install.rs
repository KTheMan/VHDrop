//! Optional, per-user installation. No changes are made until the user invokes install.
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

/// Install this executable for the current Windows user and create a Start menu shortcut.
/// Existing installed files/shortcuts with our exact names are replaced; unrelated files are not touched.
pub fn install() -> Result<String, String> {
    let source = std::env::current_exe().map_err(|e| format!("Could not locate this app: {e}"))?;
    let local = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    let roaming = std::env::var_os("APPDATA").ok_or("APPDATA is not set")?;
    let dir = PathBuf::from(local).join("Programs").join("VHDX Handoff");
    let programs = PathBuf::from(roaming)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs");
    install_to(&source, &dir, &programs)?;
    let notes = install_shell(&dir, None, None)?;
    remove_owned_legacy_shortcut(&dir, &programs)?;
    Ok(format!(
        "Installed to {} with a Start menu shortcut and VHD/VHDX mount actions. {}",
        dir.display(),
        notes
    ))
}

/// Install the small Windows mount helper and register the per-user shell actions.
/// An alternate registry root is accepted only by tests, so they never change real associations.
fn install_shell(dir: &Path, classes_root: Option<&str>, software_root: Option<&str>) -> Result<String, String> {
    let helper = dir.join("VirtualDisk.ps1");
    let setup = dir.join("shell_setup.ps1");
    fs::write(&helper, include_str!("VirtualDisk.ps1"))
        .map_err(|e| format!("App installed, but could not write the disk helper: {e}"))?;
    fs::write(&setup, include_str!("shell_setup.ps1"))
        .map_err(|e| format!("App installed, but could not write association setup: {e}"))?;
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&setup)
        .arg("-InstallDir")
        .arg(dir);
    if let Some(root) = classes_root {
        command.arg("-ClassesRoot").arg(root);
    }
    if let Some(root) = software_root {
        command.arg("-SoftwareRoot").arg(root);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let out = command
        .output()
        .map_err(|e| format!("App installed, but could not start association setup: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "App installed, but VHD/VHDX setup failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn unique_file(dir: &Path, prefix: &str, extension: &str) -> Result<(PathBuf, fs::File), String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..32 {
        let path = dir.join(format!(
            ".{prefix}-{}-{stamp}-{attempt}.{extension}",
            std::process::id()
        ));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "Could not create temporary file in {}: {e}",
                    dir.display()
                ))
            }
        }
    }
    Err(format!(
        "Could not create a unique temporary file in {}",
        dir.display()
    ))
}

fn install_to(source: &Path, dir: &Path, programs: &Path) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("Could not create install folder {}: {e}", dir.display()))?;
    fs::create_dir_all(programs).map_err(|e| {
        format!(
            "Could not create Start menu folder {}: {e}",
            programs.display()
        )
    })?;
    let target = dir.join("VHDrop.exe");
    let same = match (fs::canonicalize(source), fs::canonicalize(&target)) {
        (Ok(a), Ok(b)) => a
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy()),
        _ => false,
    };
    if !same {
        let (tmp, mut output) = unique_file(dir, "vhdx-handoff-install", "tmp")?;
        let copied = (|| -> Result<(), String> {
            let mut input =
                fs::File::open(source).map_err(|e| format!("Could not open source app: {e}"))?;
            io::copy(&mut input, &mut output).map_err(|e| format!("Could not copy app: {e}"))?;
            output
                .sync_all()
                .map_err(|e| format!("Could not flush copied app: {e}"))?;
            drop(output);
            fs::rename(&tmp, &target).map_err(|e| {
                format!(
                    "Could not replace {}: {e}. Close any installed copy and retry.",
                    target.display()
                )
            })?;
            Ok(())
        })();
        if copied.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        copied?;
    }
    let shortcut = programs.join("VHDrop.lnk");
    // Create a unique .lnk name then remove the empty reservation before COM writes it.
    let (tmp, reservation) = unique_file(programs, "vhdx-handoff-shortcut", "lnk")?;
    drop(reservation);
    fs::remove_file(&tmp).map_err(|e| {
        format!(
            "App copied to {}, but could not prepare the Start menu shortcut: {e}",
            target.display()
        )
    })?;
    let script = r#"$ErrorActionPreference='Stop'; $w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut($env:VHDX_INSTALL_LINK); $s.TargetPath=$env:VHDX_INSTALL_TARGET; $s.WorkingDirectory=$env:VHDX_INSTALL_WORKDIR; $s.IconLocation=$env:VHDX_INSTALL_TARGET+',0'; $s.Description='VHDrop'; $s.Save()"#;
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .env("VHDX_INSTALL_LINK", &tmp)
        .env("VHDX_INSTALL_TARGET", &target)
        .env("VHDX_INSTALL_WORKDIR", dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let result = (|| -> Result<(), String> {
        let out = command
            .output()
            .map_err(|e| format!("Could not start PowerShell: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "Could not create shortcut: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        if !tmp.is_file() {
            return Err("Shortcut creation did not produce a file".into());
        }
        fs::rename(&tmp, &shortcut).map_err(|e| {
            format!(
                "Could not replace Start menu shortcut {}: {e}",
                shortcut.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(|e| {
        format!(
            "App is at {}, but Start menu setup failed: {e}",
            target.display()
        )
    })
}


/// Remove only the previous app shortcut if it points at our exact legacy
/// executable. A same-named shortcut to a different target is never touched.
fn remove_owned_legacy_shortcut(dir: &Path, programs: &Path) -> Result<(), String> {
    let legacy_link = programs.join("VHDX Handoff.lnk");
    if !legacy_link.is_file() { return Ok(()); }
    let legacy_exe = dir.join("vhdx-handoff.exe");
    let script = r#"$ErrorActionPreference='Stop'; $p=$env:VHDX_LEGACY_LINK; if(-not (Test-Path -LiteralPath $p -PathType Leaf)){exit}; $s=(New-Object -ComObject WScript.Shell).CreateShortcut($p); if([string]::IsNullOrWhiteSpace($s.TargetPath)){exit}; $actual=[IO.Path]::GetFullPath($s.TargetPath); $expected=[IO.Path]::GetFullPath($env:VHDX_LEGACY_TARGET); if([StringComparer]::OrdinalIgnoreCase.Equals($actual,$expected)){Remove-Item -LiteralPath $p -Force}"#;
    let mut command = Command::new("powershell.exe");
    command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script])
        .env("VHDX_LEGACY_LINK", &legacy_link).env("VHDX_LEGACY_TARGET", &legacy_exe);
    #[cfg(windows)]
    { use std::os::windows::process::CommandExt; command.creation_flags(0x08000000); }
    let output = command.output().map_err(|e| format!("VHDrop installed, but could not inspect the previous shortcut: {e}"))?;
    if !output.status.success() { return Err(format!("VHDrop installed, but could not inspect the previous shortcut: {}", String::from_utf8_lossy(&output.stderr).trim())); }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn registers_actions_idempotently_in_an_isolated_registry_root() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("vhdx-shell-test-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let root = format!(r"HKCU:\Software\VhdxHandoffTest\test-{stamp}");
        let software_root = format!(r"{root}\Software");
        let setup = r#"$ErrorActionPreference='Stop'; $r=$env:TEST_ROOT; $soft=$env:TEST_SOFTWARE_ROOT; $reg=Join-Path $soft 'RegisteredApplications'; New-Item -Path $reg -Force | Out-Null; New-ItemProperty -Path $reg -Name 'Other Application' -Value 'Other\Capabilities' -PropertyType String -Force | Out-Null; foreach($ext in '.vhd','.vhdx'){ $p=Join-Path $r $ext; New-Item -Path $p -Force | Out-Null; Set-Item -Path $p -Value 'Existing.Handler'; New-Item -Path (Join-Path $p 'OpenWithProgids') -Force | Out-Null; New-ItemProperty -Path (Join-Path $p 'OpenWithProgids') -Name 'Other.Handler' -Value 'keep' -Force | Out-Null; $other=Join-Path $r ('SystemFileAssociations\'+$ext+'\shell\Other.Verb'); New-Item -Path $other -Force | Out-Null; Set-Item -Path $other -Value 'keep' }"#;
        let setup_result=Command::new("powershell.exe").args(["-NoProfile","-NonInteractive","-Command",setup]).env("TEST_ROOT",&root).env("TEST_SOFTWARE_ROOT",&software_root).output().unwrap();
        assert!(setup_result.status.success());
        install_shell(&dir, Some(&root), Some(&software_root)).unwrap();
        install_shell(&dir, Some(&root), Some(&software_root)).unwrap();
        let check = r#"$ErrorActionPreference='Stop'; $r=$env:TEST_ROOT; $reg=Join-Path $env:TEST_SOFTWARE_ROOT 'RegisteredApplications'; if((Get-ItemProperty -LiteralPath $reg).'Other Application' -ne 'Other\Capabilities'){throw 'Existing RegisteredApplications entry changed'}; if(-not (Get-ItemProperty -LiteralPath $reg).'VHDX Handoff'){throw 'App registration missing'}; foreach($ext in '.vhd','.vhdx'){ if((Get-Item -LiteralPath (Join-Path $r $ext)).GetValue('') -ne 'Existing.Handler'){throw 'Existing association was changed'}; if((Get-ItemProperty -LiteralPath (Join-Path (Join-Path $r $ext) 'OpenWithProgids')).'Other.Handler' -ne 'keep'){throw 'Open With entry changed'}; if((Get-Item -LiteralPath (Join-Path $r ('SystemFileAssociations\'+$ext+'\shell\Other.Verb'))).GetValue('') -ne 'keep'){throw 'Sibling verb changed'}; foreach($action in 'Mount','Dismount'){ $k=Join-Path $r ('SystemFileAssociations\'+$ext+'\shell\VHDXHandoff.'+$action+'\command'); $v=(Get-Item -LiteralPath $k).GetValue(''); if($v -notlike ('*-Action '+$action+'*') -or $v -notlike '*%1*'){throw 'Incorrect command'} } }; Remove-Item -LiteralPath $r -Recurse -Force"#;
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", check])
            .env("TEST_ROOT", &root)
            .env("TEST_SOFTWARE_ROOT", &software_root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(dir.join("VirtualDisk.ps1").is_file());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn migration_removes_only_our_legacy_shortcut() {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("vhdrop-migration-test-{}-{stamp}",std::process::id()));
        let install = root.join("install"); let programs = root.join("programs");
        fs::create_dir_all(&install).unwrap(); fs::create_dir_all(&programs).unwrap();
        let link = programs.join("VHDX Handoff.lnk");
        let create = |target: &Path| {
            let out = Command::new("powershell.exe").args(["-NoProfile","-NonInteractive","-Command", "$w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut($env:TEST_LINK); $s.TargetPath=$env:TEST_TARGET; $s.Save()"])
                .env("TEST_LINK", &link).env("TEST_TARGET", target).output().unwrap();
            assert!(out.status.success(), "{}",String::from_utf8_lossy(&out.stderr));
        };
        create(&root.join("unrelated.exe"));
        remove_owned_legacy_shortcut(&install,&programs).unwrap();
        assert!(link.is_file(), "unrelated same-named shortcut must survive");
        create(&install.join("vhdx-handoff.exe"));
        remove_owned_legacy_shortcut(&install,&programs).unwrap();
        assert!(!link.exists(), "our legacy shortcut should be replaced");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copies_and_updates_into_isolated_directories_with_valid_shortcut() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("vhdx-install-test-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source.exe");
        let install = root.join("install");
        let programs = root.join("programs");
        fs::write(&source, b"first executable").unwrap();
        install_to(&source, &install, &programs).unwrap();
        assert_eq!(
            fs::read(install.join("VHDrop.exe")).unwrap(),
            b"first executable"
        );
        let link = programs.join("VHDrop.lnk");
        assert!(link.is_file());
        let out=Command::new("powershell.exe").args(["-NoProfile","-NonInteractive","-Command","$w=New-Object -ComObject WScript.Shell; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $w.CreateShortcut($env:TEST_LINK).TargetPath"]).env("TEST_LINK",&link).output().unwrap();
        assert!(out.status.success());
        let actual_target = String::from_utf8_lossy(&out.stdout);
        let actual_target = fs::canonicalize(actual_target.trim()).expect("shortcut target must exist");
        let expected_target = fs::canonicalize(install.join("VHDrop.exe")).unwrap();
        assert!(actual_target.to_string_lossy().eq_ignore_ascii_case(&expected_target.to_string_lossy()),
            "shortcut target differs: {} vs {}", actual_target.display(), expected_target.display());
        let icon=Command::new("powershell.exe").args(["-NoProfile","-NonInteractive","-Command","$w=New-Object -ComObject WScript.Shell; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $w.CreateShortcut($env:TEST_LINK).IconLocation"]).env("TEST_LINK",&link).output().unwrap();
        assert!(icon.status.success());
        let icon_location = String::from_utf8_lossy(&icon.stdout);
        let (icon_path, icon_index) = icon_location.trim().rsplit_once(',').expect("icon must include an index");
        assert_eq!(icon_index, "0");
        let icon_path = fs::canonicalize(icon_path).expect("shortcut icon must exist");
        assert!(icon_path.to_string_lossy().eq_ignore_ascii_case(&expected_target.to_string_lossy()),
            "shortcut icon differs: {} vs {}", icon_path.display(), expected_target.display());
        fs::write(&source, b"updated executable").unwrap();
        install_to(&source, &install, &programs).unwrap();
        assert_eq!(
            fs::read(install.join("VHDrop.exe")).unwrap(),
            b"updated executable"
        );
        // Running the installed app should simply refresh its shortcut, without copying over itself.
        install_to(&install.join("VHDrop.exe"), &install, &programs).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
