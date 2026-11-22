//! Small shared helpers: command execution, file permissions, ICMP echo.

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use vw_core::packet::{checksum, fix_ipv4_header_checksum, IpView, PROTO_ICMP};
use vw_core::{Result, VwError};

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Output of an external command.
#[derive(Debug, Clone)]
pub struct CmdOut {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run a program with a timeout. Errors only when it cannot be started or
/// times out; check `success` for the exit status.
pub async fn run(program: &str, args: &[&str]) -> Result<CmdOut> {
    let fut = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .map_err(|_| VwError::Timeout)??;
    Ok(CmdOut {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Like [`run`] but a non-zero exit is an error (stderr scrubbed of addresses).
pub async fn run_ok(program: &str, args: &[&str]) -> Result<CmdOut> {
    let o = run(program, args).await?;
    if !o.success {
        return Err(VwError::Config(format!(
            "{program} failed: {}",
            vw_firewall::scrub_addresses(o.stderr.trim())
        )));
    }
    Ok(o)
}

/// Blocking variant for synchronous contexts (installer, panic paths).
pub fn run_sync(program: &str, args: &[&str]) -> Result<CmdOut> {
    let out = std::process::Command::new(program).args(args).output()?;
    Ok(CmdOut {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Who may read a protected file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// root / SYSTEM + Administrators only (0600).
    Private,
    /// Plus read for the admin group / Users (0640).
    GroupRead,
    /// Directory: 0750 with the admin group.
    Dir,
}

/// Name of the group allowed to talk to the daemon.
#[cfg(target_os = "macos")]
pub const ADMIN_GROUP: &str = "admin";
#[cfg(all(unix, not(target_os = "macos")))]
pub const ADMIN_GROUP: &str = "voidwire";

/// Write `data` atomically to `path` with the given access.
pub fn write_protected(path: &Path, data: &[u8], access: Access) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    set_access(path, access)
}

/// Apply ownership and permissions (unix) or an ACL (Windows).
pub fn set_access(path: &Path, access: Access) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = match access {
            Access::Private => 0o600,
            Access::GroupRead => 0o640,
            Access::Dir => 0o750,
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        if access != Access::Private && nix::unistd::geteuid().is_root() {
            if let Ok(Some(g)) = nix::unistd::Group::from_name(ADMIN_GROUP) {
                std::os::unix::fs::chown(path, Some(0), Some(g.gid.as_raw()))?;
            }
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        // SYSTEM (S-1-5-18), Administrators (S-1-5-32-544), Users (S-1-5-32-545).
        let p = path.to_string_lossy().into_owned();
        let mut args: Vec<&str> = vec![p.as_str(), "/inheritance:r", "/grant:r"];
        match access {
            Access::Private => args.extend(["*S-1-5-18:F", "*S-1-5-32-544:F"]),
            Access::GroupRead => args.extend(["*S-1-5-18:F", "*S-1-5-32-544:F", "*S-1-5-32-545:R"]),
            Access::Dir => args.extend([
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-5-32-545:(RX)",
            ]),
        }
        let o = run_sync("icacls", &args)?;
        if !o.success {
            return Err(VwError::Permission(format!(
                "icacls failed: {}",
                o.stderr.trim()
            )));
        }
        Ok(())
    }
}

// ───────────────────────────── ICMP echo ─────────────────────────────

/// Build an IPv4 ICMP echo request (`payload_len` bytes of payload).
pub fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, payload_len: usize) -> Vec<u8> {
    let icmp_len = 8 + payload_len;
    let total = 20 + icmp_len;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6] = 0x40;
    p[8] = vw_core::consts::TTL_NORMAL;
    p[9] = PROTO_ICMP;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20] = 8;
    p[24..26].copy_from_slice(&id.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    for (i, b) in p[28..].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(31);
    }
    let c = checksum(&p[20..]);
    p[22..24].copy_from_slice(&c.to_be_bytes());
    fix_ipv4_header_checksum(&mut p);
    p
}

/// `(type, id, seq)` of an IPv4 ICMP echo request/reply.
pub fn icmp_echo_fields(pkt: &[u8]) -> Option<(u8, u16, u16)> {
    let v = IpView::parse(pkt).ok()?;
    if v.version != 4 || v.protocol != PROTO_ICMP || v.l4_offset + 8 > v.total_len {
        return None;
    }
    let o = v.l4_offset;
    let ty = pkt[o];
    if ty != 0 && ty != 8 {
        return None;
    }
    Some((
        ty,
        u16::from_be_bytes([pkt[o + 4], pkt[o + 5]]),
        u16::from_be_bytes([pkt[o + 6], pkt[o + 7]]),
    ))
}

/// Turn an echo request into the matching reply (used by test nodes and
/// local responders).
pub fn icmp_reply_for(req: &[u8]) -> Option<Vec<u8>> {
    let (ty, _, _) = icmp_echo_fields(req)?;
    if ty != 8 {
        return None;
    }
    let v = IpView::parse(req).ok()?;
    let mut r = req[..v.total_len].to_vec();
    let (s, d) = (r[12..16].to_vec(), r[16..20].to_vec());
    r[12..16].copy_from_slice(&d);
    r[16..20].copy_from_slice(&s);
    let o = v.l4_offset;
    r[o] = 0;
    r[o + 2] = 0;
    r[o + 3] = 0;
    let c = checksum(&r[o..]);
    r[o + 2..o + 4].copy_from_slice(&c.to_be_bytes());
    fix_ipv4_header_checksum(&mut r);
    Some(r)
}

/// Random ephemeral port in the dynamic range.
pub fn ephemeral_port() -> u16 {
    rand::Rng::gen_range(&mut rand::rngs::OsRng, 49152..=65000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_roundtrip() {
        let a = Ipv4Addr::new(100, 96, 0, 2);
        let b = Ipv4Addr::new(100, 96, 0, 1);
        let req = icmp_echo(a, b, 7, 9, 56);
        assert_eq!(icmp_echo_fields(&req), Some((8, 7, 9)));
        assert_eq!(checksum(&req[..20]), 0);
        assert_eq!(checksum(&req[20..]), 0);
        let rep = icmp_reply_for(&req).unwrap();
        assert_eq!(icmp_echo_fields(&rep), Some((0, 7, 9)));
        let v = IpView::parse(&rep).unwrap();
        assert_eq!(v.src, std::net::IpAddr::V4(b));
        assert_eq!(checksum(&rep[20..]), 0);
        assert!(icmp_reply_for(&rep).is_none());
    }
}
