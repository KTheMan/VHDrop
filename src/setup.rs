//! Host-side setup transport. Uses existing OpenSSH keys/agent, never passwords.
use crate::config::Config;
use std::{io::{Read, Write}, process::{Command, Stdio}, time::{Duration, Instant}};

pub fn validate(c: &Config) -> Result<(), String> {
    validate_host(&c.copy_ssh)?;
    let root=c.guest_root.trim();
    if !root.starts_with('/') || root=="/" || root.contains(['\n','\r','\0']) || root.split('/').any(|v|v=="."||v=="..") {
        return Err("Enter an absolute, canonical Linux share directory, other than /.".into());
    }
    let share=c.share.trim().replace('/', "\\");
    let parts:Vec<_>=share.strip_prefix("\\\\").unwrap_or("").split('\\').collect();
    if parts.len()<2 || parts[0].is_empty() || parts[1].is_empty() || parts.iter().any(|s|*s=="."||*s=="..") {
        return Err("Enter a UNC share such as \\\\server\\share.".into());
    }
    Ok(())
}
fn validate_host(host:&str)->Result<(),String> {
    let h=host.trim();
    if h.is_empty() || h.starts_with('-') || !h.bytes().all(|x|x.is_ascii_alphanumeric() || b"@._-".contains(&x)) {
        return Err("Enter an SSH host such as user@nas (using an existing key and known host).".into());
    }
    Ok(())
}
fn quote(v:&str)->String { format!("'{}'",v.replace('\'', "'\\''")) }
/// Stream bundled helper sources through SSH. Setup never requests/stores credentials
/// and never escalates privileges. A separate explicit root preparation may be required.
pub fn copy_helper(c:&Config, install:bool)->Result<String,String> {
    validate(c)?;
    let script=setup_script(install,c.guest_root.trim())?;
    let stdout=remote_script(c.copy_ssh.trim(), script, if install {Duration::from_secs(600)} else {Duration::from_secs(45)})?;
    if stdout.lines().any(|x|x.trim()=="VHDX_HANDOFF_COPY_READY") { Ok("Copy helper verified for this share.".into()) }
    else { Err("Host check did not report readiness.".into()) }
}
fn setup_script(install:bool, root:&str)->Result<String,String> {
    let setup=include_str!("../server/setup_copy.py");
    let helper=include_str!("../server/vhdx-copy");
    let marker="__VHDX_HANDOFF_SOURCE_4819A2B7__";
    if setup.contains(marker)||helper.contains(marker)||!setup.ends_with('\n')||!helper.ends_with('\n') { return Err("Invalid embedded helper payload.".into()); }
    Ok(if install {
        format!("set -eu\numask 077\nstage=$(mktemp -d \"${{TMPDIR:-/tmp}}/vhdx-handoff.XXXXXXXX\")\ncleanup() {{ rm -f -- \"$stage/setup_copy.py\" \"$stage/vhdx-copy\"; rmdir -- \"$stage\" 2>/dev/null || :; }}\ntrap cleanup EXIT\ncat > \"$stage/setup_copy.py\" <<'{marker}'\n{setup}{marker}\ncat > \"$stage/vhdx-copy\" <<'{marker}'\n{helper}{marker}\n/usr/bin/python3 -I \"$stage/setup_copy.py\" --install --root {}\n",quote(root))
    } else {
        // Run the verifier embedded in this binary, not a mutable installed checker.
        format!("exec /usr/bin/python3 -I -c {} --check --root {}\n",quote(setup),quote(root))
    })
}
pub fn guarded_command(host:&str, command:&str)->Result<String,String> {
    guarded_command_timeout(host,command,Duration::from_secs(45))
}
pub fn guarded_command_timeout(host:&str, command:&str, limit:Duration)->Result<String,String> {
    validate_host(host)?;
    remote_script(host.trim(), format!("{command}\n"), limit)
}
fn remote_script(host:&str, script:String, limit:Duration)->Result<String,String> {
    validate_host(host)?;
    let mut cmd=Command::new("ssh.exe");
    cmd.args(["-T","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","ConnectTimeout=8","-o","ServerAliveInterval=15","-o","ServerAliveCountMax=3","-a",host,"sh -s"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)] { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }
    let mut child=cmd.spawn().map_err(|e|format!("Could not start SSH: {e}"))?;
    let out=child.stdout.take().ok_or("SSH output unavailable")?;
    let err=child.stderr.take().ok_or("SSH error output unavailable")?;
    let stdout=std::thread::spawn(move||drain_tail(out));
    let stderr=std::thread::spawn(move||drain_tail(err));
    let mut stdin=child.stdin.take().ok_or("SSH input unavailable")?;
    // A separate writer lets the timeout kill SSH even if its pipe stops draining.
    let writer=std::thread::spawn(move || stdin.write_all(script.as_bytes()));
    let started=Instant::now();
    let mut timed_out=false;
    let status=loop {
        match child.try_wait() {
            Ok(Some(s))=>break s,
            Ok(None) if started.elapsed()<limit=>std::thread::sleep(Duration::from_millis(100)),
            Ok(None)=>{timed_out=true;let _=child.kill();break child.wait().map_err(|e|e.to_string())?;},
            Err(e)=>{let _=child.kill();let _=child.wait();return Err(format!("SSH setup failed: {e}"));},
        }
    };
    let sent=writer.join().map_err(|_|"SSH setup writer failed".to_string())?;
    let stdout=stdout.join().unwrap_or_default(); let stderr=stderr.join().unwrap_or_default();
    if timed_out {return Err("Host setup timed out. The remote operation may still be running; inspect it before retrying.".into());}
    if let Err(e)=sent {return Err(format!("Could not send host setup: {e}"));}
    if status.success() { Ok(stdout) } else {
        let msg=stderr.lines().rev().find(|s|!s.trim().is_empty()).unwrap_or("Remote check failed.");
        Err(format!("{msg} (SSH exit: {status})"))
    }
}

fn guard_share(value:&str)->Result<(String,String),String> {
    let share=value.replace('/', "\\");
    let parts:Vec<_>=share.strip_prefix(r"\\").unwrap_or("").split('\\').collect();
    if parts.len()!=2 || parts.iter().any(|x|x.is_empty()||*x=="."||*x=="..") {
        return Err("Use a root UNC share (\\\\server\\share) for guarded operations.".into());
    }
    Ok((parts[0].to_string(),parts[1].to_string()))
}
/// Provision the optional, topology-specific root guard from the exact bundled
/// installer and hash-checked payload. Never accepts passwords or arbitrary code.
pub fn install_guard(c:&Config)->Result<String,String> {
    let script=guard_install_script(c)?;
    let output=remote_script(c.delete_ssh.trim(),script,Duration::from_secs(180))?;
    if output.lines().any(|line|line.trim()=="VHDX_HANDOFF_GUARD_INSTALLED") {Ok("Host guard installed. Detach and verify an image before deletion.".into())}
    else {Err("The host guard installer did not report success.".into())}
}
fn guard_install_script(c:&Config)->Result<String,String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    validate(c)?; validate_host(&c.delete_ssh)?;
    if c.delete_helper != "/opt/vhdx-handoff-v1/vhdx_delete.py" {
        return Err("Use the bundled versioned host guard path.".into());
    }
    if !c.host_root.starts_with('/') || c.host_root=="/" || c.host_root.contains(['\n','\r','\0','\\']) || c.host_root.split('/').any(|x|x=="."||x=="..") {
        return Err("Enter the canonical non-root share directory on the host.".into());
    }
    let (smb_host,smb_share)=guard_share(&c.share)?;
    if c.guard_container_id.len()>12 || !c.guard_container_id.bytes().all(|b|b.is_ascii_digit()) {
        return Err("Enter a numeric Proxmox LXC guest ID, or leave it blank for Samba on the host.".into());
    }
    if c.guard_container_id.is_empty() && c.host_root != c.guest_root {
        return Err("For Samba on the host, the host and Linux share directories must match.".into());
    }
    if c.guard_guest_username.is_empty() || c.guard_guest_username.len()>64 || !c.guard_guest_username.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b)) {
        return Err("Enter the guest SMB username (without a password).".into());
    }
    if !c.guard_guest_smb_acknowledged {return Err("Explicitly acknowledge the guest-SMB trusted-network requirement.".into());}
    let files:[(&str,&[u8]);7]=[
        ("vhdx_delete.py",include_bytes!("../server/vhdx_delete.py")),
        ("delete_inside_mount.py",include_bytes!("../server/delete_inside_mount.py")),
        ("operation_state.py",include_bytes!("../server/operation_state.py")),
        ("smb_guard.py",include_bytes!("../server/smb_guard.py")),
        ("host_config.py",include_bytes!("../server/host_config.py")),
        ("pyspnego-0.12.4-py3-none-any.whl",include_bytes!("../server/vendor-wheels/pyspnego-0.12.4-py3-none-any.whl")),
        ("smbprotocol-1.17.0-py3-none-any.whl",include_bytes!("../server/vendor-wheels/smbprotocol-1.17.0-py3-none-any.whl")),
    ];
    let mut map=serde_json::Map::new();
    for (name,data) in files {map.insert(name.into(),serde_json::Value::String(STANDARD.encode(data)));}
    let config=serde_json::json!({"local_root":c.host_root,"guest_root":c.guest_root,
        "smb_host":smb_host,"smb_share":smb_share,"container_id":c.guard_container_id,
        "guest_username":c.guard_guest_username,"guest_smb_acknowledged":true});
    let payload=serde_json::json!({"config":config,"files":map}).to_string();
    let marker="__VHDX_GUARD_REQUEST_27B41C6D__";
    if payload.contains(marker) {return Err("Invalid guard request.".into());}
    let source=include_str!("../server/setup_guard.py");
    Ok(format!("set -eu\nif [ \"$(id -u)\" = 0 ]; then set -- /usr/bin/python3; else set -- sudo -n /usr/bin/python3; fi\nexec \"$@\" -I -c {} --install <<'{marker}'\n{payload}\n{marker}\n",quote(source)))
}

/// Prove both the source directory and destination mapping on every copy.
/// Each nonce is opened CREATE_NEW and DELETE_ON_CLOSE, so cleanup applies to
/// our original open object even if a path is renamed or replaced.
#[cfg(windows)]
pub fn verify_copy_mapping(c:&Config, image:&str, destination:&str)->Result<(),String> {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt, path::Path};
    #[link(name="bcrypt")] unsafe extern "system" { fn BCryptGenRandom(algorithm:*mut core::ffi::c_void,buffer:*mut u8,len:u32,flags:u32)->i32; }
    validate(c)?;
    let image_dir=Path::new(image).parent().ok_or("Cannot determine the image directory.")?;
    let locations=[("image directory",image_dir.to_string_lossy().into_owned()),("destination",destination.to_string())];
    for (label,win_dir) in locations {
        let linux_dir=crate::translate(&win_dir,&c.share,&c.guest_root)
            .map_err(|e|format!("Cannot verify {label}: {e}"))?;
        let mut random=[0u8;16];
        if unsafe { BCryptGenRandom(std::ptr::null_mut(),random.as_mut_ptr(),random.len() as u32,2) } < 0 {
            return Err("Could not generate a secure mapping probe; copy did not start.".into());
        }
        let token:String=random.iter().map(|x|format!("{x:02x}")).collect();
        let name=format!(".vhdx-handoff-probe-{token}");
        let path=Path::new(&win_dir).join(&name);
        let mut probe=OpenOptions::new().write(true).create_new(true)
            .access_mode(0x4000_0000 | 0x0001_0000) // GENERIC_WRITE | DELETE
            .share_mode(0x0000_0001 | 0x0000_0002 | 0x0000_0004)
            .custom_flags(0x0400_0000) // FILE_FLAG_DELETE_ON_CLOSE
            .open(&path).map_err(|e|format!("Cannot verify {label} mapping: cannot create temporary probe in {win_dir}: {e}. Write access is needed in both the image directory and destination; copy did not start."))?;
        let result=(|| -> Result<String,String> {
            probe.write_all(token.as_bytes()).and_then(|_|probe.sync_all())
                .map_err(|e|format!("Cannot write {label} mapping probe: {e}"))?;
            let remote_path=format!("{}/{}",linux_dir.trim_end_matches('/'),name);
            let py="import os,stat,sys; f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW); s=os.fstat(f); b=os.read(f,65); os.close(f); assert stat.S_ISREG(s.st_mode) and b==sys.argv[2].encode(); print('VHDX_MAPPING_OK')";
            let script=format!("exec /usr/bin/python3 -I -c {} {} {}\n",quote(py),quote(&remote_path),quote(&token));
            remote_script(c.copy_ssh.trim(),script,Duration::from_secs(45))
        })();
        drop(probe); // Delete only the original probe object, even on failure.
        match path.try_exists() {
            Ok(false)=>{},
            Ok(true)=>return Err(format!("Temporary {label} probe {} still exists after closing; inspect it before retrying. Copy did not start.",path.display())),
            Err(e)=>return Err(format!("Could not confirm cleanup of temporary {label} probe {}: {e}. Inspect it before retrying; copy did not start.",path.display())),
        }
        let output=result.map_err(|e|format!("Cannot verify {label} mapping: {e}; copy did not start."))?;
        if !output.lines().any(|l|l.trim()=="VHDX_MAPPING_OK") {
            return Err(format!("Windows {label} does not match configured host directory {linux_dir}; copy did not start."));
        }
    }
    Ok(())
}
#[cfg(not(windows))]
pub fn verify_copy_mapping(_: &Config, _: &str, _: &str)->Result<(),String> {
    Err("Windows mapping verification is unavailable on this platform.".into())
}
// The trusted bundled root-preparation code is passed inline. Never execute a
// user-writable uploaded installer as root; the path is separately quoted data.
const ROOT_PREP: &str = include_str!("../server/prepare_copy_root.py");
fn drain_tail(mut r: impl Read)->String {
    let mut tail=Vec::new();let mut buf=[0u8;4096];
    while let Ok(n)=r.read(&mut buf) {if n==0 {break;} tail.extend_from_slice(&buf[..n]);if tail.len()>16384 {tail.drain(..tail.len()-16384);}}
    String::from_utf8_lossy(&tail).into_owned()
}
pub fn root_command(c:&Config)->String {
    format!("sudo /usr/bin/python3 -I -c {} {}",quote(ROOT_PREP),quote(c.guest_root.trim()))
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn validation_rejects_incomplete_and_traversal() {
        let mut c=Config::default();assert!(validate(&c).is_err());c.copy_ssh="user@example.test".into();c.share=r"\\server\share".into();c.guest_root="/srv/share".into();assert!(validate(&c).is_ok());
        c.guest_root="/srv/../other".into();assert!(validate(&c).is_err());c.guest_root="/".into();assert!(validate(&c).is_err());
        c.guest_root="/srv/share".into();c.copy_ssh="-bad".into();assert!(validate(&c).is_err());
    }
    #[test] fn guard_share_requires_complete_unc_root() {
        assert_eq!(guard_share(r"\\server\share").unwrap(),("server".into(),"share".into()));
        assert!(guard_share(r"\server\share").is_err());
        assert!(guard_share(r"\\server\share\child").is_err());
        assert!(guard_share(r"\\server\..").is_err());
    }
    #[test] fn guard_bundle_matches_configuration_and_embedded_files() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut c=Config::default();c.copy_ssh="user@example.test".into();c.share=r"\\server\share".into();
        c.guest_root="/srv/guest".into();c.delete_ssh="root@example.test".into();c.host_root="/srv/host".into();
        c.guard_container_id="101".into();c.guard_guest_username="guest".into();c.guard_guest_smb_acknowledged=true;
        let script=guard_install_script(&c).unwrap();
        let marker="__VHDX_GUARD_REQUEST_27B41C6D__";
        let start=format!("--install <<'{marker}'\n");
        let payload=script.split_once(&start).unwrap().1.split_once(&format!("\n{marker}\n")).unwrap().0;
        let request:serde_json::Value=serde_json::from_str(payload).unwrap();
        assert_eq!(request["config"]["smb_host"],"server");assert_eq!(request["config"]["smb_share"],"share");
        assert_eq!(request["config"]["local_root"],"/srv/host");assert_eq!(request["config"]["guest_root"],"/srv/guest");
        let files=[("vhdx_delete.py",include_bytes!("../server/vhdx_delete.py").as_slice()),
                   ("delete_inside_mount.py",include_bytes!("../server/delete_inside_mount.py").as_slice()),
                   ("operation_state.py",include_bytes!("../server/operation_state.py").as_slice()),
                   ("smb_guard.py",include_bytes!("../server/smb_guard.py").as_slice()),
                   ("host_config.py",include_bytes!("../server/host_config.py").as_slice()),
                   ("pyspnego-0.12.4-py3-none-any.whl",include_bytes!("../server/vendor-wheels/pyspnego-0.12.4-py3-none-any.whl").as_slice()),
                   ("smbprotocol-1.17.0-py3-none-any.whl",include_bytes!("../server/vendor-wheels/smbprotocol-1.17.0-py3-none-any.whl").as_slice())];
        for (name,expected) in files {assert_eq!(STANDARD.decode(request["files"][name].as_str().unwrap()).unwrap(),expected);}
        c.share=r"\server\share".into();assert!(guard_install_script(&c).is_err());
        c.share=r"\\server\share".into();c.delete_ssh="-bad".into();assert!(guard_install_script(&c).is_err());
        c.delete_ssh="root@example.test".into();c.guard_guest_smb_acknowledged=false;assert!(guard_install_script(&c).is_err());
    }
    #[test] fn local_samba_guard_requires_the_same_share_root() {
        let mut c=Config::default(); c.copy_ssh="user@example.test".into(); c.share=r"\\server\share".into();
        c.guest_root="/srv/share".into(); c.delete_ssh="root@example.test".into(); c.host_root=c.guest_root.clone();
        c.guard_guest_username="guest".into(); c.guard_guest_smb_acknowledged=true;
        assert!(guard_install_script(&c).is_ok());
        c.host_root="/srv/other".into(); assert!(guard_install_script(&c).is_err());
        c.guard_container_id="101".into(); assert!(guard_install_script(&c).is_ok());
        c.guard_container_id="invalid".into(); assert!(guard_install_script(&c).is_err());
    }
    #[test] fn install_uploads_exact_bundled_bytes() {
        let script=setup_script(true,"/srv/example").unwrap();
        assert!(script.contains("/usr/bin/python3 -I \"$stage/setup_copy.py\""));
        let marker="__VHDX_HANDOFF_SOURCE_4819A2B7__";
        for (filename,expected) in [("setup_copy.py",include_str!("../server/setup_copy.py")),("vhdx-copy",include_str!("../server/vhdx-copy"))] {
            let start=format!("cat > \"$stage/{filename}\" <<'{marker}'\n");
            let after=script.split_once(&start).expect("upload header").1;
            let content=after.split_once(&format!("{marker}\n")).expect("upload terminator").0;
            assert_eq!(content.as_bytes(),expected.as_bytes());
        }
        let check=setup_script(false,"/srv/example").unwrap();
        assert!(!check.contains("mkdir -p"));
    }
    #[test] fn shell_quote_escapes_single_quotes() {assert_eq!(quote("a'b"),"'a'\\''b'");}
}

