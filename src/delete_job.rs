//! Host-side deletion and recovery preflight for an explicitly configured share.
use crate::{delete_ui::DeleteTarget, windows};
use std::{
    net::{IpAddr, ToSocketAddrs},
    process::Command,
};

#[cfg(windows)]
pub(crate) fn final_path(path: &str) -> Result<String, String> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut std::ffi::c_void,
            creation: u32,
            flags: u32,
            template: *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void;
        fn GetFinalPathNameByHandleW(
            handle: *mut std::ffi::c_void,
            name: *mut u16,
            len: u32,
            flags: u32,
        ) -> u32;
        fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
    }
    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            7,
            std::ptr::null_mut(),
            3,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(format!(
            "Cannot safely resolve image path: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut buf = vec![0u16; 32768];
    let len = unsafe { GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), buf.len() as u32, 0) };
    unsafe {
        CloseHandle(handle);
    }
    if len == 0 || len as usize >= buf.len() {
        return Err(format!(
            "Cannot resolve the final image path: {}",
            std::io::Error::last_os_error()
        ));
    }
    let value = String::from_utf16(&buf[..len as usize]).map_err(|_| "Invalid final image path")?;
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        return Ok(format!(r"\\{}", rest));
    }
    if let Some(rest) = value.strip_prefix(r"\\?\") {
        let b = rest.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
            return Ok(rest.to_string());
        }
        return Err("Unrecognized device path; cannot verify image safety.".into());
    }
    Err("Unrecognized final image path; cannot verify image safety.".into())
}
#[cfg(not(windows))]
pub(crate) fn final_path(path: &str) -> Result<String, String> {
    Ok(path.to_string())
}

#[cfg(windows)]
fn current_unc(path: &str) -> Result<Option<String>, String> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDriveTypeW(root: *const u16) -> u32;
    }
    #[link(name = "mpr")]
    unsafe extern "system" {
        fn WNetGetConnectionW(local: *const u16, remote: *mut u16, len: *mut u32) -> u32;
    }
    let p = path.replace('/', "\\");
    if p.starts_with(r"\\") {
        return Ok(Some(p));
    }
    let bytes = p.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err("Choose a fully qualified image path.".into());
    }
    let root = format!("{}:\\", bytes[0] as char);
    let root_w: Vec<u16> = std::ffi::OsStr::new(&root)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let ty = unsafe { GetDriveTypeW(root_w.as_ptr()) };
    match ty {
        4 => {
            let local = format!("{}:", bytes[0] as char);
            let local_w: Vec<u16> = std::ffi::OsStr::new(&local)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let mut buf = vec![0u16; 32768];
            let mut len = buf.len() as u32;
            let err = unsafe { WNetGetConnectionW(local_w.as_ptr(), buf.as_mut_ptr(), &mut len) };
            if err != 0 {
                return Err(format!(
                    "Cannot verify mapped drive {local} (Windows error {err})."
                ));
            }
            let end = buf.iter().position(|x| *x == 0).unwrap_or(buf.len());
            let remote =
                String::from_utf16(&buf[..end]).map_err(|_| "Invalid mapped drive path")?;
            Ok(Some(format!(
                "{}{}",
                remote.trim_end_matches('\\'),
                &p[2..]
            )))
        }
        2 | 3 | 5 | 6 => Ok(None),
        _ => Err(format!("Cannot verify drive {root} before mounting.")),
    }
}
#[cfg(not(windows))]
fn current_unc(path: &str) -> Result<Option<String>, String> {
    if path.starts_with(r"\\") {
        Ok(Some(path.to_string()))
    } else {
        Ok(None)
    }
}

/// Resolve only the explicitly configured network share. A different or
/// ambiguous hostname fails closed; no guessed path mapping authorizes writes.
fn protected_path(config: &crate::config::Config, path: &str, linux_root: &str, deletion: bool) -> Result<Option<String>, String> {
    let Some(unc) = current_unc(path)? else { return Ok(None); };
    if !(if deletion { config.delete_configured() } else { config.copy_configured() }) {
        return Err("Network image safety cannot be verified until the host guard is configured and checked.".into());
    }
    let configured = config.share.replace('/', "\\");
    let share_parts: Vec<&str> = configured.trim_start_matches('\\').split('\\').collect();
    let parts: Vec<&str> = unc.trim_start_matches('\\').split('\\').collect();
    if !configured.starts_with(r"\\") || share_parts.len() != 2 || parts.len() < 3
        || share_parts.iter().any(|p| p.is_empty() || *p == "." || *p == "..") {
        return Err("Configure a fully qualified SMB share before using the host guard.".into());
    }
    let same_host = same_server(parts[0], share_parts[0])?;
    if !same_host || !parts[1].eq_ignore_ascii_case(share_parts[1]) {
        return Err("The image is not on the configured protected share; recovery cannot be verified.".into());
    }
    valid_absolute_path(linux_root)?;
    let canonical = format!(r"\\{}\{}\{}", share_parts[0], share_parts[1], parts[2..].join("\\"));
    Ok(Some(crate::translate(&canonical, &configured, linux_root)?))
}

fn addresses(host: &str) -> Result<std::collections::BTreeSet<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() { return Ok([ip].into_iter().collect()); }
    let result: std::collections::BTreeSet<IpAddr> = (host, 445).to_socket_addrs()
        .map_err(|e| format!("Cannot resolve SMB server {host}: {e}"))?.map(|a| a.ip()).collect();
    if result.is_empty() { return Err("SMB server resolved to no addresses.".into()); }
    Ok(result)
}

fn same_server(a: &str, b: &str) -> Result<bool, String> {
    Ok(a.eq_ignore_ascii_case(b) || addresses(a)? == addresses(b)?)
}
fn valid_absolute_path(value: &str) -> Result<(), String> {
    if !value.starts_with('/') || value == "/" || value.contains(['\0','\r','\n','\\'])
        || value.split('/').any(|x| x == "." || x == "..") {
        return Err("Use an absolute, non-root Linux path without relative components.".into());
    }
    Ok(())
}
fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.starts_with('-') || !host.bytes().all(|x| x.is_ascii_alphanumeric() || b"@._-".contains(&x)) {
        return Err("Use an ordinary SSH user@host or host name.".into());
    }
    Ok(())
}
fn ssh(host: &str, remote: &str) -> Result<String, String> {
    validate_host(host)?;
    crate::setup::guarded_command(host, remote)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardDescription {
    version: u32,
    smb_host: String,
    smb_share: String,
    local_root: String,
    guest_root: String,
    config_sha256: String,
}
fn validate_description(config: &crate::config::Config, desc: &GuardDescription) -> Result<String, String> {
    let share = config.share.replace('/', "\\");
    let parts: Vec<_> = share.strip_prefix(r"\\").unwrap_or("").split('\\').collect();
    if parts.len() != 2 || parts.iter().any(|p| p.is_empty())
        || desc.version != 1 || desc.local_root != config.host_root
        || desc.guest_root != config.guest_root || !desc.smb_share.eq_ignore_ascii_case(parts[1])
        || !same_server(&desc.smb_host, parts[0])?
        || desc.config_sha256.len() != 64 || !desc.config_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Host guard configuration does not match the selected share and Linux directories.".into());
    }
    Ok(desc.config_sha256.to_ascii_lowercase())
}
const TRUSTED_HELPER: &str = "/opt/vhdx-handoff-v1/vhdx_delete.py";
fn guard_prefix(config: &crate::config::Config) -> Result<&'static str, String> {
    let uid = ssh(&config.delete_ssh, "/usr/bin/id -u")?;
    let uid: u32 = uid.trim().parse().map_err(|_| "Could not determine host SSH user identity.")?;
    Ok(if uid == 0 { "" } else { "/usr/bin/sudo -n -- " })
}
fn guard_digest(config: &crate::config::Config, prefix: &str) -> Result<String, String> {
    if config.delete_helper != TRUSTED_HELPER { return Err("Use the helper path installed by this version of VHDrop.".into()); }
    if !config.delete_configured() { return Err("Complete and verify guarded host setup first.".into()); }
    valid_absolute_path(&config.delete_helper)?;
    let out = ssh(&config.delete_ssh, &format!("{}{} --describe", prefix, crate::quote(&config.delete_helper)))?;
    if out.len() > 8192 { return Err("Host guard returned an invalid description.".into()); }
    let desc: GuardDescription = serde_json::from_str(&out).map_err(|_| "Host guard returned an invalid description.")?;
    validate_description(config, &desc)
}
/// Verify the selected image with the root-owned guard and matching config digest.
pub fn check_guard(config: &crate::config::Config, path: &str) -> Result<(), String> {
    let canonical = final_path(path)?;
    let image = protected_path(config, &canonical, &config.host_root, true)?
        .ok_or("Host guard applies only to the configured network share.")?;
    let prefix = guard_prefix(config)?;
    let digest = guard_digest(config, prefix)?;
    check_status(config, &image, &digest, prefix)
}
fn check_status(config: &crate::config::Config, image: &str, digest: &str, prefix: &str) -> Result<(), String> {
    if config.delete_helper != TRUSTED_HELPER { return Err("Unrecognized host guard path.".into()); }
    // Run the verifier bundled with this Windows build over the existing SSH
    // connection. It verifies root-owned helper hashes before requesting the
    // digest-bound exclusive guard/status check on the actual image.
    let verifier = include_str!("../server/setup_guard.py");
    let remote = format!("exec {}/usr/bin/python3 -I -c {} --check --image {} --expected-config-digest {}", prefix, crate::quote(verifier), crate::quote(image), crate::quote(digest));
    let out = crate::setup::guarded_command_timeout(&config.delete_ssh, &remote, std::time::Duration::from_secs(120))?;
    if !out.lines().any(|line| line.trim() == "VHDX_HANDOFF_GUARD_READY") {
        return Err("Host guard did not report a verified image state; operation blocked.".into());
    }
    Ok(())
}
/// Local images do not use host guard; network images fail closed if unverifiable.
pub fn check_before_mount(path: &str) -> Result<(), String> {
    let canonical = final_path(path)?;
    if current_unc(&canonical)?.is_none() { return Ok(()); }
    let config = crate::config::Config::load()?.unwrap_or_default();
    check_guard(&config, &canonical)
}
#[cfg(test)]
fn remote_command(config: &crate::config::Config, target: &DeleteTarget, partition: u32) -> Result<String, String> {
    remote_command_for_path(config, target, partition, &target.image_path, &"a".repeat(64), "")
}
fn remote_command_for_path(
    config: &crate::config::Config,
    target: &DeleteTarget,
    partition: u32,
    image_path: &str,
    digest: &str,
    prefix: &str,
) -> Result<String, String> {
    if !target.image_path.to_ascii_lowercase().ends_with(".vhdx") {
        return Err("Host deletion currently supports VHDX images only.".into());
    }
    if !(1..=128).contains(&partition) {
        return Err("Invalid partition number.".into());
    }
    validate_host(&config.delete_ssh)?;
    valid_absolute_path(&config.delete_helper)?;
    let image = protected_path(config, image_path, &config.host_root, true)?
        .ok_or("Host deletion is available for the configured protected share only.")?;
    Ok(format!(
        "{}{} --expected-config-digest {} -- {} {} {} {}",
        prefix,
        crate::quote(&config.delete_helper),
        crate::quote(digest),
        crate::quote(&image),
        partition,
        crate::quote(&target.relative_path),
        if target.is_dir { "dir" } else { "file" }
    ))
}
pub fn run(
    config: &crate::config::Config,
    target: &DeleteTarget,
    partition: u32,
    log: std::sync::mpsc::Sender<String>,
) -> Result<String, String> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let canonical = final_path(&target.image_path)?;
    let prefix = guard_prefix(config)?;
    let digest = guard_digest(config, prefix)?;
    let image = protected_path(config, &canonical, &config.host_root, true)?.ok_or("Image is not on the configured share.")?;
    check_status(config, &image, &digest, prefix)?;
    let remote = remote_command_for_path(config, target, partition, &canonical, &digest, prefix)?;
    if windows::image_attached(&target.image_path)? {
        return Err("The image is attached in Windows; detach it before deleting.".into());
    }
    let mut cmd = Command::new("ssh.exe");
    cmd.args([
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=8",
        "-a",
        &config.delete_ssh,
        &remote,
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Could not start host SSH: {e}"))?;
    let stdout = child.stdout.take().ok_or("Could not capture host output")?;
    let stderr = child.stderr.take().ok_or("Could not capture host errors")?;
    let tx = log.clone();
    let out_reader = std::thread::spawn(move || {
        let mut tail = String::new();
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line.clone());
            if tail.len() < 4096 {
                tail.push_str(&line);
                tail.push('\n');
            }
        }
        tail
    });
    let err_reader = std::thread::spawn(move || {
        let mut tail = String::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = log.send(line.clone());
            if tail.len() < 4096 {
                tail.push_str(&line);
                tail.push('\n');
            }
        }
        tail
    });
    let status = child
        .wait()
        .map_err(|e| format!("Host connection failed: {e}"))?;
    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    if !status.success() {
        return Err(format!("Host deletion did not complete cleanly ({status}). The image may have changed or the host may still be working. Keep it detached and inspect the host before retrying. {} {}",stdout.trim(),stderr.trim()));
    }
    Ok(format!(
        "Deleted {}. The image is detached.",
        target.relative_path
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_path_resolves_existing_local_file_and_rejects_missing() {
        let root =
            std::env::temp_dir().join(format!("vhdx-final-path-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("disk.vhdx");
        std::fs::write(&file, b"fixture").unwrap();
        let resolved = final_path(&file.to_string_lossy()).unwrap();
        assert!(resolved.to_ascii_lowercase().ends_with("disk.vhdx"));
        assert!(final_path(&root.join("missing.vhdx").to_string_lossy()).is_err());
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn configured_share_and_quoted_paths() {
        let cfg = crate::config::Config { copy_ssh: "copy@server".into(), share: r"\\192.0.2.10\shared".into(), guest_root: "/srv/shared".into(), delete_ssh: "guard@server".into(), host_root: "/srv/storage".into(), ..Default::default() };
        let target = DeleteTarget::new(r"\\192.0.2.10\shared\disk.vhdx".into(), r"project\Bob's file".into(), false).unwrap();
        assert_eq!(protected_path(&cfg, &target.image_path, &cfg.guest_root, false).unwrap().unwrap(), "/srv/shared/disk.vhdx");
        let cmd = remote_command(&cfg, &target, 2).unwrap();
        assert!(cmd.contains("/srv/storage/disk.vhdx"));
        assert!(cmd.contains("Bob'\\''s file"));
        let mut bad = target.clone();
        bad.image_path = r"\\192.0.2.11\shared\a.vhdx".into();
        assert!(remote_command(&cfg, &bad, 2).is_err());
        assert!(remote_command(&Default::default(), &target, 2).is_err());
        assert!(valid_absolute_path("/srv/../other").is_err());
        assert!(validate_host("-oProxyCommand=bad").is_err());
        let mut desc = GuardDescription { version: 1, smb_host: "192.0.2.10".into(), smb_share: "shared".into(), local_root: "/srv/storage".into(), guest_root: "/srv/shared".into(), config_sha256: "a".repeat(64) };
        assert!(validate_description(&cfg, &desc).is_ok());
        desc.guest_root = "/wrong".into();
        assert!(validate_description(&cfg, &desc).is_err());
    }
}
