//! Runtime facts for the signed attestation (PROMPT.md §2.6).
//!
//! The parsers are pure functions over file contents so they are testable on
//! every OS; [`collect`] reads the real files on Linux. On other systems the
//! facts that cannot be established are reported as `false`.

use std::path::Path;

use vw_core::Result;

/// `statfs` magic numbers of RAM-backed filesystems.
pub const TMPFS_MAGIC: u64 = 0x0102_1994;
pub const RAMFS_MAGIC: u64 = 0x8584_58f6;

/// True for tmpfs / ramfs.
pub fn is_ram_fs_magic(magic: u64) -> bool {
    magic == TMPFS_MAGIC || magic == RAMFS_MAGIC
}

/// `/proc/swaps` lists one active swap area per line after the header.
pub fn swap_disabled_from_proc_swaps(contents: &str) -> bool {
    contents.lines().skip(1).all(|l| l.trim().is_empty())
}

/// Seconds from the first field of `/proc/uptime`.
pub fn parse_proc_uptime(contents: &str) -> Option<u64> {
    let first = contents.split_whitespace().next()?;
    let secs: f64 = first.parse().ok()?;
    (secs.is_finite() && secs >= 0.0).then_some(secs as u64)
}

/// The value of `Storage=` in the `[Journal]` section of one config file
/// (the last assignment wins), if any.
pub fn journald_storage_in(contents: &str) -> Option<String> {
    let mut in_journal = false;
    let mut value = None;
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_journal = line.eq_ignore_ascii_case("[Journal]");
            continue;
        }
        if !in_journal {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "Storage" {
                value = Some(v.trim().to_ascii_lowercase());
            }
        }
    }
    value
}

/// Effective journald `Storage=` per systemd's rules: the main file, then
/// drop-ins in lexicographic filename order (a file in an earlier directory
/// masks a same-named file in later ones; callers pass them already merged).
/// Default when unset is `auto`.
pub fn effective_journald_storage(main: Option<&str>, dropins: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = dropins.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut storage = main.and_then(journald_storage_in);
    for (_, c) in sorted {
        if let Some(v) = journald_storage_in(c) {
            storage = Some(v);
        }
    }
    storage.unwrap_or_else(|| "auto".into())
}

/// Logging is off when journald is absent or configured with `Storage=none`.
pub fn logging_off(journald_present: bool, storage: &str) -> bool {
    !journald_present || storage == "none"
}

/// Facts that go into an [`vw_crypto::AttestationReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub binary_blake3: String,
    pub swap_disabled: bool,
    pub logging_off: bool,
    pub ram_only: bool,
    pub uptime_secs: u64,
}

/// BLAKE3 of a file, lowercase hex.
pub fn hash_file(path: &Path) -> Result<String> {
    let mut h = blake3::Hasher::new();
    let mut f = std::fs::File::open(path)?;
    std::io::copy(&mut f, &mut h)?;
    Ok(h.finalize().to_hex().to_string())
}

/// BLAKE3 of the running executable.
pub fn self_binary_hash() -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        hash_file(Path::new("/proc/self/exe"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        hash_file(&std::env::current_exe()?)
    }
}

/// Filesystem magic of the filesystem holding `path` (Linux).
#[cfg(target_os = "linux")]
pub fn fs_magic(path: &Path) -> Result<u64> {
    let s = rustix::fs::statfs(path).map_err(std::io::Error::from)?;
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    Ok(s.f_type as i64 as u64 & 0xffff_ffff)
}

/// Whether `path` lives on tmpfs/ramfs. Always false off Linux.
pub fn is_ram_backed(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        fs_magic(path).map(is_ram_fs_magic).unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        false
    }
}

/// Whether swap is disabled (reads `/proc/swaps`; false off Linux).
pub fn swap_disabled() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/swaps")
            .map(|s| swap_disabled_from_proc_swaps(&s))
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn read_dropins() -> Vec<(String, String)> {
    let mut seen = std::collections::BTreeMap::new();
    for dir in [
        "/etc/systemd/journald.conf.d",
        "/run/systemd/journald.conf.d",
        "/usr/local/lib/systemd/journald.conf.d",
        "/usr/lib/systemd/journald.conf.d",
        "/lib/systemd/journald.conf.d",
    ] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".conf") || seen.contains_key(&name) {
                continue;
            }
            if let Ok(c) = std::fs::read_to_string(e.path()) {
                seen.insert(name, c);
            }
        }
    }
    seen.into_iter().collect()
}

/// Whether persistent logging is off (journald absent or `Storage=none`).
pub fn journald_logging_off() -> bool {
    #[cfg(target_os = "linux")]
    {
        let present = Path::new("/run/systemd/journal").exists()
            || Path::new("/lib/systemd/systemd-journald").exists()
            || Path::new("/usr/lib/systemd/systemd-journald").exists();
        let main = std::fs::read_to_string("/etc/systemd/journald.conf").ok();
        let storage = effective_journald_storage(main.as_deref(), &read_dropins());
        logging_off(present, &storage)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// System uptime in seconds (`/proc/uptime`; 0 off Linux).
pub fn uptime_secs() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| parse_proc_uptime(&s))
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Collect live facts. `binary_blake3` is computed once at startup and passed in.
pub fn collect(binary_blake3: &str, state_dir: &Path) -> Facts {
    Facts {
        binary_blake3: binary_blake3.to_string(),
        swap_disabled: swap_disabled(),
        logging_off: journald_logging_off(),
        ram_only: is_ram_backed(state_dir),
        uptime_secs: uptime_secs(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_swaps() {
        let off = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
        assert!(swap_disabled_from_proc_swaps(off));
        assert!(swap_disabled_from_proc_swaps(""));
        let on = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/swap.img                               file\t\t2097148\t\t0\t\t-2\n";
        assert!(!swap_disabled_from_proc_swaps(on));
    }

    #[test]
    fn proc_uptime() {
        assert_eq!(parse_proc_uptime("12345.67 54321.00\n"), Some(12345));
        assert_eq!(parse_proc_uptime("0.10 0.00"), Some(0));
        assert_eq!(parse_proc_uptime("garbage"), None);
        assert_eq!(parse_proc_uptime(""), None);
        assert_eq!(parse_proc_uptime("-5 1"), None);
    }

    #[test]
    fn journald_parsing() {
        let main = "#  This file is part of systemd.\n[Journal]\n#Storage=auto\n#Compress=yes\n";
        assert_eq!(journald_storage_in(main), None);
        assert_eq!(effective_journald_storage(Some(main), &[]), "auto");
        let set = "[Journal]\nStorage=persistent\n";
        assert_eq!(effective_journald_storage(Some(set), &[]), "persistent");
        let drop = vec![
            (
                "00-voidwire.conf".to_string(),
                "[Journal]\nStorage=none\nForwardToSyslog=no\n".to_string(),
            ),
            (
                "10-other.conf".to_string(),
                "[Journal]\nSystemMaxUse=10M\n".to_string(),
            ),
        ];
        assert_eq!(effective_journald_storage(Some(set), &drop), "none");
        // Later drop-ins override earlier ones regardless of input order.
        let mut drop2 = drop.clone();
        drop2.insert(
            0,
            (
                "99-late.conf".into(),
                "[Journal]\nStorage=volatile\n".into(),
            ),
        );
        assert_eq!(effective_journald_storage(Some(set), &drop2), "volatile");
        // Keys outside [Journal] are ignored.
        assert_eq!(journald_storage_in("[Other]\nStorage=none\n"), None);
        assert_eq!(
            journald_storage_in("[Journal]\n Storage = None \n").as_deref(),
            Some("none")
        );
        assert!(logging_off(true, "none"));
        assert!(logging_off(false, "persistent"));
        assert!(!logging_off(true, "auto"));
        assert!(!logging_off(true, "volatile"));
    }

    #[test]
    fn fs_magic_values() {
        assert!(is_ram_fs_magic(0x0102_1994));
        assert!(is_ram_fs_magic(0x8584_58f6));
        assert!(!is_ram_fs_magic(0xEF53)); // ext4
    }

    #[test]
    fn self_hash_is_hex() {
        let h = self_binary_hash().unwrap();
        assert_eq!(h.len(), 64);
        assert!(h
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
