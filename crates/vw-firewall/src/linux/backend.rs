//! nftables + policy-routing executor (Linux only).

use std::path::Path;

use vw_core::Result;

use super::nft::{parse_nft_table, render_nft, render_nft_teardown, NFT_FAMILY, NFT_TABLE};
use super::policy::{parse_guard_active, render_policy_routing, render_policy_teardown, Family};
use super::{IP_PATHS, NFT_PATHS};
use crate::cmd::{resolve, run, run_ok};
use crate::plan::{FirewallStatus, LockdownPlan};
use crate::FirewallBackend;

pub struct NftablesBackend {
    nft: String,
    ip: String,
    plan: Option<LockdownPlan>,
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NftablesBackend {
    pub fn new() -> Self {
        Self {
            nft: resolve("nft", &NFT_PATHS),
            ip: resolve("ip", &IP_PATHS),
            plan: None,
        }
    }

    fn families() -> Vec<Family> {
        // Without an IPv6 stack there is nothing to route (or leak) over v6.
        if Path::new("/proc/net/if_inet6").exists() {
            vec![Family::V4, Family::V6]
        } else {
            vec![Family::V4]
        }
    }

    fn rule_show(&self, f: Family) -> Result<String> {
        Ok(run_ok(&self.ip, &[f.flag(), "rule", "show"], None)?.stdout)
    }

    fn teardown_routing(&self, strict: bool) -> Result<()> {
        for f in Self::families() {
            let show = self.rule_show(f)?;
            for a in render_policy_teardown(&show, f) {
                let argv: Vec<&str> = a.iter().map(String::as_str).collect();
                // `route flush` of an empty table may fail harmlessly; a rule
                // that cannot be deleted during disarm is a real error.
                if strict && argv.get(1) == Some(&"rule") {
                    run_ok(&self.ip, &argv, None)?;
                } else {
                    run(&self.ip, &argv, None)?;
                }
            }
        }
        Ok(())
    }

    fn apply(&mut self, plan: &LockdownPlan) -> Result<()> {
        plan.validate()?;
        // 1. Atomic kernel lockdown first: from here on everything is blocked.
        let ruleset = render_nft(plan);
        run_ok(&self.nft, &["-f", "-"], Some(ruleset.as_bytes()))?;
        tracing::debug!("nftables lockdown table committed");
        // 2. Policy routing (defence in depth). A failure leaves nft locked.
        self.teardown_routing(false)?;
        for f in Self::families() {
            for a in render_policy_routing(plan, f) {
                let argv: Vec<&str> = a.iter().map(String::as_str).collect();
                run_ok(&self.ip, &argv, None)?;
            }
        }
        tracing::debug!("policy routing installed");
        self.plan = Some(plan.clone());
        Ok(())
    }
}

impl FirewallBackend for NftablesBackend {
    fn name(&self) -> &'static str {
        "nftables"
    }

    fn arm(&mut self, plan: &LockdownPlan) -> Result<()> {
        self.apply(plan)
    }

    fn update(&mut self, plan: &LockdownPlan) -> Result<()> {
        self.apply(plan)
    }

    fn disarm(&mut self) -> Result<()> {
        // Routing first: while the table still exists nothing can leak.
        self.teardown_routing(true)?;
        run_ok(
            &self.nft,
            &["-f", "-"],
            Some(render_nft_teardown().as_bytes()),
        )?;
        self.plan = None;
        tracing::debug!("nftables lockdown removed");
        Ok(())
    }

    fn status(&self) -> Result<FirewallStatus> {
        let armed = self.is_armed_in_kernel()?;
        let guard = Self::families()
            .into_iter()
            .map(|f| self.rule_show(f).map(|s| parse_guard_active(&s)))
            .collect::<Result<Vec<bool>>>()?
            .into_iter()
            .all(|b| b);
        Ok(FirewallStatus::from_plan(
            self.name(),
            self.plan.as_ref(),
            armed,
            armed && guard,
        ))
    }

    fn is_armed_in_kernel(&self) -> Result<bool> {
        let out = run(&self.nft, &["list", "table", NFT_FAMILY, NFT_TABLE], None)?;
        if !out.success {
            return Ok(false);
        }
        Ok(parse_nft_table(&out.stdout).is_locked())
    }
}
