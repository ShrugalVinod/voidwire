//! pf executor (macOS only).
//!
//! Arm order (each step fail-closed with respect to the previous one):
//! 1. write `/etc/pf.anchors/com.voidwire.lockdown` and load it with
//!    `pfctl -a com.voidwire.lockdown -f -` (one atomic ruleset swap);
//! 2. back up `/etc/pf.conf` once, insert the managed block referencing the
//!    anchor, and reload the main ruleset if it does not reference it yet;
//! 3. enable pf with `pfctl -E`, keeping the reference token in the state dir
//!    so disarm releases exactly our reference with `pfctl -X <token>`.

use std::path::{Path, PathBuf};

use vw_core::{Result, VwError};

use super::pf::{
    anchor_is_locked, inject_managed_block, main_references_anchor, parse_pf_enabled,
    parse_pf_token, render_pf_anchor, strip_managed_block, PF_ANCHOR, PF_ANCHOR_FILE, PF_CONF,
};
use crate::cmd::{run, run_ok, write_atomic};
use crate::plan::{FirewallStatus, LockdownPlan};
use crate::FirewallBackend;

const PFCTL: &str = "/sbin/pfctl";

pub struct PfBackend {
    state_dir: PathBuf,
    pf_conf: PathBuf,
    anchor_file: PathBuf,
    plan: Option<LockdownPlan>,
}

impl Default for PfBackend {
    fn default() -> Self {
        Self::new(vw_core::paths::state_dir())
    }
}

impl PfBackend {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            pf_conf: PathBuf::from(PF_CONF),
            anchor_file: PathBuf::from(PF_ANCHOR_FILE),
            plan: None,
        }
    }

    fn token_file(&self) -> PathBuf {
        self.state_dir.join("pf.token")
    }

    fn backup_file(&self) -> PathBuf {
        self.state_dir.join("pf.conf.voidwire-backup")
    }

    fn pf_enabled() -> Result<bool> {
        let out = run_ok(PFCTL, &["-s", "info"], None)?;
        Ok(parse_pf_enabled(&out.combined()))
    }

    fn ensure_pf_conf(&self) -> Result<()> {
        let current = std::fs::read_to_string(&self.pf_conf)?;
        let backup = self.backup_file();
        if !backup.exists() {
            write_atomic(&backup, strip_managed_block(&current).as_bytes())?;
        }
        let anchor_file = self.anchor_file.to_string_lossy();
        let wanted = inject_managed_block(&current, &anchor_file);
        if wanted != current {
            write_atomic(&self.pf_conf, wanted.as_bytes())?;
        }
        let main = run_ok(PFCTL, &["-s", "rules"], None)?;
        if !main_references_anchor(&main.stdout) {
            let conf = self.pf_conf.to_string_lossy();
            run_ok(PFCTL, &["-f", &conf], None)?;
            tracing::debug!("pf main ruleset reloaded with VoidWire anchor reference");
        }
        Ok(())
    }

    fn ensure_enabled(&self) -> Result<()> {
        let token_file = self.token_file();
        if token_file.exists() && Self::pf_enabled()? {
            return Ok(());
        }
        let out = run_ok(PFCTL, &["-E"], None)?;
        let token = parse_pf_token(&out.combined())
            .ok_or_else(|| VwError::Firewall("pfctl -E returned no reference token".into()))?;
        write_atomic(&token_file, token.as_bytes())?;
        Ok(())
    }

    fn apply(&mut self, plan: &LockdownPlan) -> Result<()> {
        plan.validate()?;
        let rules = render_pf_anchor(plan);
        write_atomic(&self.anchor_file, rules.as_bytes())?;
        run_ok(PFCTL, &["-a", PF_ANCHOR, "-f", "-"], Some(rules.as_bytes()))?;
        self.ensure_pf_conf()?;
        self.ensure_enabled()?;
        self.plan = Some(plan.clone());
        tracing::debug!("pf lockdown anchor loaded");
        Ok(())
    }

    fn remove_if_exists(p: &Path) -> Result<()> {
        match std::fs::remove_file(p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

impl FirewallBackend for PfBackend {
    fn name(&self) -> &'static str {
        "pf"
    }

    fn arm(&mut self, plan: &LockdownPlan) -> Result<()> {
        self.apply(plan)
    }

    fn update(&mut self, plan: &LockdownPlan) -> Result<()> {
        self.apply(plan)
    }

    fn disarm(&mut self) -> Result<()> {
        // Flush only our anchor's rules (global state table is left alone).
        run_ok(PFCTL, &["-a", PF_ANCHOR, "-F", "rules"], None)?;
        if let Ok(current) = std::fs::read_to_string(&self.pf_conf) {
            let stripped = strip_managed_block(&current);
            if stripped != current {
                write_atomic(&self.pf_conf, stripped.as_bytes())?;
            }
        }
        Self::remove_if_exists(&self.anchor_file)?;
        let token_file = self.token_file();
        if let Ok(token) = std::fs::read_to_string(&token_file) {
            // A token from before a reboot is no longer valid; that is fine.
            let out = run(PFCTL, &["-X", token.trim()], None)?;
            if !out.success {
                tracing::debug!("pf reference token already released");
            }
        }
        Self::remove_if_exists(&token_file)?;
        self.plan = None;
        tracing::debug!("pf lockdown removed");
        Ok(())
    }

    fn status(&self) -> Result<FirewallStatus> {
        let armed = self.is_armed_in_kernel()?;
        // pf's default-deny does not depend on the routing table, so rogue
        // DHCP routes cannot bypass it (Tunnelvision guard = armed).
        Ok(FirewallStatus::from_plan(
            self.name(),
            self.plan.as_ref(),
            armed,
            armed,
        ))
    }

    fn is_armed_in_kernel(&self) -> Result<bool> {
        if !Self::pf_enabled()? {
            return Ok(false);
        }
        let main = run_ok(PFCTL, &["-s", "rules"], None)?;
        if !main_references_anchor(&main.stdout) {
            return Ok(false);
        }
        let anchor = run_ok(PFCTL, &["-a", PF_ANCHOR, "-s", "rules"], None)?;
        Ok(anchor_is_locked(&anchor.stdout))
    }
}
