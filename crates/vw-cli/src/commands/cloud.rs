//! `voidwire cloud generate`: write a RAM-only node deployment bundle locally.

use std::path::{Path, PathBuf};

use serde_json::json;
use vw_core::config::Bytes32;
use vw_freecloud::cloud::{generate_bundle, BundleOptions, Provider};

use crate::cli::CloudArgs;
use crate::exit::{CliError, CliResult, ExitCode};
use crate::output::Out;

/// Why `--authorize-me` cannot work without `--owner-key` today.
pub const OWNER_KEY_GAP: &str = "voidwired does not expose this device's WireGuard public key over IPC \
(no Request returns it and StatusReport does not carry it), so the CLI cannot look it up for --authorize-me. \
Pass it explicitly with --owner-key <base64>.";

/// Remedy printed alongside [`OWNER_KEY_GAP`].
pub const OWNER_KEY_WORKAROUND: &str =
    "Without an owner key you can still use the node: after deploying, create an invite on it \
(`sudo voidwire-node invite --state /run/voidwire --bandwidth-limit 1Gbps --expires 1d`) \
and redeem it here with `voidwire invite redeem <uri>`.";

/// Build [`BundleOptions`] from the command line (pure apart from reading
/// the SSH public key file).
pub fn bundle_options(args: &CloudArgs, default_version: &str) -> CliResult<BundleOptions> {
    let owner_key = match (&args.owner_key, args.authorize_me) {
        (Some(k), _) => {
            let k = k.trim();
            if Bytes32::from_base64(k).is_none() {
                return Err(CliError::usage(
                    "--owner-key must be a 32-byte WireGuard public key in base64",
                ));
            }
            Some(k.to_string())
        }
        (None, true) => {
            return Err(CliError::usage(OWNER_KEY_GAP).with_hint(OWNER_KEY_WORKAROUND));
        }
        (None, false) => None,
    };
    let provider: Provider = args.provider.into();
    let version = args
        .release_version
        .as_deref()
        .unwrap_or(default_version)
        .trim();
    let mut o = BundleOptions::new(provider, version);
    if let Some(n) = &args.name {
        o.node_name = n.clone();
    }
    o.region = args.region.clone();
    o.owner_wg_public_key = owner_key;
    if let Some(p) = &args.ssh_key {
        o.ssh_public_key = Some(read_ssh_public_key(p)?);
    }
    Ok(o)
}

pub fn read_ssh_public_key(path: &Path) -> CliResult<String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::usage(format!("cannot read SSH key {}: {e}", path.display())))?;
    if text.contains("PRIVATE KEY") {
        return Err(CliError::usage(format!(
            "{} is a private key; pass the public key (usually the .pub file)",
            path.display()
        )));
    }
    let key = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| CliError::usage(format!("{} contains no key", path.display())))?;
    Ok(key.to_string())
}

/// The "## Deploy" section of the generated README (single source of truth
/// for next steps).
pub fn deploy_steps(readme: &str) -> Option<&str> {
    let start = readme.find("## Deploy")?;
    let body = readme[start + "## Deploy".len()..].trim_start_matches('\n');
    let end = body.find("\n## ").unwrap_or(body.len());
    Some(body[..end].trim_end())
}

pub fn run(out: &mut Out, args: &CloudArgs) -> CliResult<i32> {
    let opts = bundle_options(args, env!("CARGO_PKG_VERSION"))?;
    let bundle = generate_bundle(&opts).map_err(|e| CliError::usage(e.to_string()))?;
    let dir: PathBuf = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("voidwire-node-{}", args.provider.slug())));
    if !args.force {
        let existing: Vec<String> = bundle
            .files
            .iter()
            .map(|f| dir.join(&f.path))
            .filter(|p| p.exists())
            .map(|p| p.display().to_string())
            .collect();
        if !existing.is_empty() {
            return Err(CliError::new(
                ExitCode::Usage,
                format!("refusing to overwrite {}", existing.join(", ")),
            )
            .with_hint("Pick another --out directory or pass --force."));
        }
    }
    let written = bundle
        .write_to(&dir)
        .map_err(|e| CliError::failure(format!("writing bundle to {}: {e}", dir.display())))?;
    let provider = opts.provider;
    if out.json {
        out.emit_json(&json!({
            "provider": provider,
            "out_dir": dir,
            "files": written,
            "version": opts.version,
            "node_name": opts.node_name,
            "owner_preauthorized": opts.owner_wg_public_key.is_some(),
            "cost_note": provider.cost_note(),
        }));
        return Ok(ExitCode::Success.code());
    }
    let t = out.theme;
    out.line(&t.ok(&format!(
        "✓ wrote {} files for {} to {}",
        written.len(),
        args.provider.slug(),
        dir.display()
    )));
    for p in &written {
        out.line(&format!("  {}", p.display()));
    }
    out.line("");
    out.line(&format!("{} {}", t.warn("cost:"), provider.cost_note()));
    if let Some(steps) = bundle.get("README.md").and_then(deploy_steps) {
        out.line("");
        out.line(&t.bold("Next steps"));
        for l in steps.lines() {
            out.line(&format!("  {l}"));
        }
    }
    out.line("");
    if opts.owner_wg_public_key.is_some() {
        out.line(&t.dim("This device's key is pre-authorised as the node owner (--authorize)."));
    } else {
        out.line(&t.dim(OWNER_KEY_WORKAROUND));
    }
    out.line(&t.dim("Then import the node URI with `voidwire nodes import <uri>`."));
    Ok(ExitCode::Success.code())
}
