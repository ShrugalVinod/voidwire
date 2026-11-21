//! Running system tools (`nft`, `ip`, `pfctl`, `route`, `networksetup`,
//! `netsh`, ...) without a shell, and scrubbing addresses from their output
//! before it can reach an error message or log line.

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Stdio};

use vw_core::{Result, VwError};

/// Captured result of a finished command.
#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    /// stdout followed by stderr (some tools, e.g. `pfctl -E`, report on stderr).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn combined(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// Run `program args...`, optionally feeding `stdin`. Fails only when the
/// process cannot be spawned; a non-zero exit is reported in `CmdOutput`.
pub fn run(program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<CmdOutput> {
    tracing::trace!(program, nargs = args.len(), "spawning system tool");
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = cmd
        .spawn()
        .map_err(|e| VwError::Firewall(format!("cannot run {program}: {e}")))?;
    if let Some(input) = stdin {
        let mut pipe = child
            .stdin
            .take()
            .ok_or_else(|| VwError::Firewall(format!("{program}: stdin unavailable")))?;
        pipe.write_all(input)
            .map_err(|e| VwError::Firewall(format!("{program}: writing stdin: {e}")))?;
        drop(pipe);
    }
    let out = child
        .wait_with_output()
        .map_err(|e| VwError::Firewall(format!("{program}: {e}")))?;
    Ok(CmdOutput {
        success: out.status.success(),
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Like [`run`], but a non-zero exit becomes `VwError::Firewall` carrying the
/// tool's stderr with every address scrubbed.
pub fn run_ok(program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<CmdOutput> {
    let out = run(program, args, stdin)?;
    if out.success {
        Ok(out)
    } else {
        let sub = args.first().copied().unwrap_or("");
        // Some tools (netsh, networksetup) report errors on stdout.
        let diag = if out.stderr.trim().is_empty() {
            out.stdout.trim()
        } else {
            out.stderr.trim()
        };
        Err(VwError::Firewall(format!(
            "{program} {sub} exited with {:?}: {}",
            out.code,
            scrub_addresses(diag)
        )))
    }
}

/// First existing absolute path among `candidates`, else the bare `name`
/// (resolved through `PATH`). Daemons often run with a minimal `PATH`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn resolve(name: &str, candidates: &[&str]) -> String {
    candidates
        .iter()
        .find(|c| std::path::Path::new(c).is_file())
        .map(|c| (*c).to_string())
        .unwrap_or_else(|| name.to_string())
}

/// Write `contents` to `path` via a temporary file + rename so readers (and
/// a crash) never observe a half-written file.
pub fn write_atomic(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| VwError::Firewall("path has no parent directory".into()))?;
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| VwError::Firewall("path has no file name".into()))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".voidwire-tmp");
    let tmp = dir.join(tmp_name);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn addr_char(c: char) -> bool {
    c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '/' | '%' | '[' | ']')
}

fn looks_like_addr(run: &str) -> bool {
    if !(run.contains('.') || run.contains(':')) {
        return false;
    }
    if run.parse::<SocketAddr>().is_ok() {
        return true;
    }
    let core = run.trim_matches(|c| c == '[' || c == ']' || c == '.' || c == ':');
    let core = core.split('/').next().unwrap_or(core);
    let core = core.split('%').next().unwrap_or(core);
    if core.parse::<IpAddr>().is_ok() {
        return true;
    }
    if let Some((host, port)) = core.rsplit_once(':') {
        return port.parse::<u16>().is_ok() && host.parse::<IpAddr>().is_ok();
    }
    false
}

/// Replace every IPv4/IPv6 address, CIDR or socket address in `text` with
/// `<addr>` so tool diagnostics can be surfaced at `warn`/`error` safely.
pub fn scrub_addresses(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if !run.is_empty() {
            if looks_like_addr(run) {
                out.push_str("<addr>");
            } else {
                out.push_str(run);
            }
            run.clear();
        }
    };
    for c in text.chars() {
        if addr_char(c) {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_all_address_forms() {
        let s = scrub_addresses(
            "Error: ip daddr 198.51.100.7 udp dport 51820; [2001:db8::7]:443 via fe80::1%en0 net 10.0.0.0/8 to 203.0.113.99:53",
        );
        assert!(!s.contains("198.51"), "{s}");
        assert!(!s.contains("2001:db8"), "{s}");
        assert!(!s.contains("fe80"), "{s}");
        assert!(!s.contains("10.0.0.0"), "{s}");
        assert!(!s.contains("203.0.113"), "{s}");
        assert!(s.contains("dport 51820"));
    }

    #[test]
    fn keeps_non_addresses() {
        let s = "line 10: syntax error at 12:30, cafe beef 1.5x";
        assert_eq!(scrub_addresses(s), s);
    }

    #[test]
    fn atomic_write_roundtrip() {
        let dir = std::env::temp_dir().join(format!("vwfw-test-{}", std::process::id()));
        let p = dir.join("x.json");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_falls_back_to_name() {
        assert_eq!(
            resolve("definitely-not-a-tool", &["/nonexistent/x"]),
            "definitely-not-a-tool"
        );
    }
}
