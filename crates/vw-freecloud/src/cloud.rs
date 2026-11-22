//! Free-tier `voidwire-node` deployment bundles.
//!
//! Every bundle provisions the node in volatile RAM-only mode: state under
//! `/run/voidwire` (tmpfs), swap disabled and masked, journald `Storage=none`,
//! rsyslog disabled, core dumps disabled, BBR congestion control, and all
//! transports enabled (WireGuard/AmneziaWG on UDP 51820, MASQUE on UDP 443,
//! TLS-WebSocket with decoy site on TCP 443).
//!
//! Honest cost notes are embedded in each bundle's README:
//! * Oracle Cloud Always Free: Ampere A1 (up to 4 OCPU / 24 GB) and 10 TB/month
//!   egress — the best $0 option.
//! * Google Cloud Free Tier: one e2-micro in us-west1/us-central1/us-east1, but
//!   only 1 GB/month free egress; beyond that you are billed.
//! * Fly.io: no free allowance for new organisations; small machines are cheap
//!   but not $0.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vw_core::consts::{DEFAULT_MASQUE_PORT, DEFAULT_NODE_UDP_PORT, DEFAULT_TLS_PORT};
use vw_core::{Result, VwError};

/// Default location of release artifacts (overridable per bundle).
pub const DEFAULT_RELEASE_BASE: &str = "https://github.com/ShrugalVinod/voidwire/releases/download";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    OracleFree,
    GcpFree,
    Fly,
    /// Any Linux VPS with Docker (compose file).
    Docker,
    /// Any Linux VPS reachable over SSH (bootstrap script only).
    Ssh,
}

impl Provider {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "oracle-free" | "oracle" | "oci" => Ok(Provider::OracleFree),
            "gcp-free" | "gcp" | "google" => Ok(Provider::GcpFree),
            "fly" | "fly.io" => Ok(Provider::Fly),
            "docker" => Ok(Provider::Docker),
            "ssh" | "vps" => Ok(Provider::Ssh),
            _ => Err(VwError::Config(format!(
                "unknown provider '{s}' (oracle-free, gcp-free, fly, docker, ssh)"
            ))),
        }
    }

    pub const fn cost_note(self) -> &'static str {
        match self {
            Provider::OracleFree => "Oracle Cloud Always Free: Ampere A1 Flex (4 OCPU / 24 GB) and 10 TB/month outbound data at $0. Recommended.",
            Provider::GcpFree => "Google Cloud Free Tier: one e2-micro in us-west1, us-central1 or us-east1 at $0, but only 1 GB/month of free outbound data — heavier use is billed.",
            Provider::Fly => "Fly.io has no free allowance for new organisations; a shared-cpu-1x machine plus a dedicated IPv4 costs a few dollars per month.",
            Provider::Docker | Provider::Ssh => "Runs on any Linux VPS you already have; cost depends on your provider.",
        }
    }
}

/// Options for [`generate_bundle`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleOptions {
    pub provider: Provider,
    pub node_name: String,
    /// Release version without the leading `v`, e.g. `0.1.0`.
    pub version: String,
    pub release_base: String,
    /// Provider region (e.g. `us-ashburn-1`, `us-west1`, `fra`).
    pub region: Option<String>,
    /// SSH public key installed for the default user.
    pub ssh_public_key: Option<String>,
    /// Client WireGuard public key (base64) pre-authorised as the node owner.
    pub owner_wg_public_key: Option<String>,
    pub udp_port: u16,
    pub tls_port: u16,
    pub quic_port: u16,
    /// SNI presented by the TLS-WS / MASQUE listeners (cover domain).
    pub sni: String,
}

impl BundleOptions {
    pub fn new(provider: Provider, version: &str) -> Self {
        Self {
            provider,
            node_name: "voidwire-node".into(),
            version: version.trim_start_matches('v').to_string(),
            release_base: DEFAULT_RELEASE_BASE.into(),
            region: None,
            ssh_public_key: None,
            owner_wg_public_key: None,
            udp_port: DEFAULT_NODE_UDP_PORT,
            tls_port: DEFAULT_TLS_PORT,
            quic_port: DEFAULT_MASQUE_PORT,
            sni: "www.example.com".into(),
        }
    }

    fn validate(&self) -> Result<()> {
        let safe = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        };
        if !safe(&self.node_name) || self.node_name.len() > 48 {
            return Err(VwError::Config(
                "node name must be 1-48 chars of [A-Za-z0-9._-]".into(),
            ));
        }
        if !safe(&self.version) {
            return Err(VwError::Config("invalid version".into()));
        }
        if !safe(&self.sni) {
            return Err(VwError::Config("invalid SNI".into()));
        }
        if let Some(r) = &self.region {
            if !safe(r) {
                return Err(VwError::Config("invalid region".into()));
            }
        }
        if !self.release_base.starts_with("https://")
            || self.release_base.contains(['\'', '"', '`', '$', ' ', '\n'])
        {
            return Err(VwError::Config(
                "release base must be a plain https URL".into(),
            ));
        }
        if let Some(k) = &self.owner_wg_public_key {
            if vw_core::config::Bytes32::from_base64(k).is_none() {
                return Err(VwError::Config("owner key must be 32-byte base64".into()));
            }
        }
        if let Some(k) = &self.ssh_public_key {
            if k.contains(['\n', '\'', '"', '`', '$'])
                || !k.starts_with("ssh-") && !k.starts_with("ecdsa-")
            {
                return Err(VwError::Config("invalid SSH public key".into()));
            }
        }
        if self.udp_port == 0 || self.tls_port == 0 || self.quic_port == 0 {
            return Err(VwError::Config("ports must be non-zero".into()));
        }
        Ok(())
    }
}

/// A set of generated files.
#[derive(Debug, Clone, Default)]
pub struct Bundle {
    pub files: Vec<BundleFile>,
}

#[derive(Debug, Clone)]
pub struct BundleFile {
    pub path: PathBuf,
    pub contents: String,
    pub executable: bool,
}

impl Bundle {
    fn add(&mut self, path: &str, contents: String, executable: bool) {
        self.files.push(BundleFile {
            path: PathBuf::from(path),
            contents,
            executable,
        });
    }

    pub fn get(&self, path: &str) -> Option<&str> {
        self.files
            .iter()
            .find(|f| f.path == Path::new(path))
            .map(|f| f.contents.as_str())
    }

    /// Write all files below `dir` (created if needed).
    pub fn write_to(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        std::fs::create_dir_all(dir)?;
        let mut written = Vec::new();
        for f in &self.files {
            let p = dir.join(&f.path);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&p, &f.contents)?;
            #[cfg(unix)]
            if f.executable {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))?;
            }
            written.push(p);
        }
        Ok(written)
    }
}

/// Generate a deployment bundle for the chosen provider.
pub fn generate_bundle(opts: &BundleOptions) -> Result<Bundle> {
    opts.validate()?;
    let mut b = Bundle::default();
    let install = install_script(opts);
    match opts.provider {
        Provider::OracleFree => {
            b.add("cloud-init.yaml", cloud_init(opts, &install, true), false);
            b.add("main.tf", oracle_tf(opts), false);
            b.add("bootstrap.sh", bootstrap_sh(opts, &install, true), true);
        }
        Provider::GcpFree => {
            b.add("cloud-init.yaml", cloud_init(opts, &install, false), false);
            b.add("main.tf", gcp_tf(opts), false);
            b.add("bootstrap.sh", bootstrap_sh(opts, &install, false), true);
        }
        Provider::Fly => {
            b.add("fly.toml", fly_toml(opts), false);
            b.add("Dockerfile", dockerfile(opts), false);
        }
        Provider::Docker => {
            b.add("docker-compose.yml", compose(opts), false);
            b.add("Dockerfile", dockerfile(opts), false);
        }
        Provider::Ssh => {
            b.add("bootstrap.sh", bootstrap_sh(opts, &install, false), true);
        }
    }
    b.add("README.md", readme(opts), false);
    Ok(b)
}

/// The node command line shared by every provider.
fn node_flags(o: &BundleOptions) -> String {
    let mut f = format!(
        "--state /run/voidwire --ram-only --name {} --listen-udp 0.0.0.0:{} --listen-quic 0.0.0.0:{} --listen-tls 0.0.0.0:{} --sni {}",
        o.node_name, o.udp_port, o.quic_port, o.tls_port, o.sni
    );
    if let Some(k) = &o.owner_wg_public_key {
        let _ = write!(f, " --authorize {k}");
    }
    f
}

/// Shell script that hardens the host for RAM-only operation and installs the
/// node from the release (with SHA-256 verification).
fn install_script(o: &BundleOptions) -> String {
    format!(
        r#"set -euo pipefail
VW_VERSION='{ver}'
VW_BASE='{base}'
case "$(uname -m)" in
  x86_64|amd64) VW_ARCH=x86_64 ;;
  aarch64|arm64) VW_ARCH=aarch64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
# --- volatile RAM-only hardening ---
swapoff -a
sed -i.bak '/\sswap\s/d' /etc/fstab
systemctl mask swap.target >/dev/null 2>&1 || true
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=none\nForwardToSyslog=no\nForwardToWall=no\n' > /etc/systemd/journald.conf.d/00-voidwire.conf
systemctl restart systemd-journald
rm -rf /var/log/journal
systemctl disable --now rsyslog >/dev/null 2>&1 || true
printf '* hard core 0\n' > /etc/security/limits.d/90-voidwire.conf
cat > /etc/sysctl.d/90-voidwire.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=7500000
net.core.wmem_max=7500000
vm.swappiness=0
kernel.core_pattern=|/bin/false
fs.suid_dumpable=0
SYSCTL
sysctl --system >/dev/null
# --- install voidwire-node ---
TMP="$(mktemp -d)"
PKG="voidwire-node-${{VW_VERSION}}-${{VW_ARCH}}-linux-musl"
curl -fsSL "${{VW_BASE}}/v${{VW_VERSION}}/${{PKG}}.tar.gz" -o "$TMP/$PKG.tar.gz"
curl -fsSL "${{VW_BASE}}/v${{VW_VERSION}}/${{PKG}}.tar.gz.sha256" -o "$TMP/$PKG.tar.gz.sha256"
(cd "$TMP" && sha256sum -c "$PKG.tar.gz.sha256")
tar -xzf "$TMP/$PKG.tar.gz" -C "$TMP"
install -m 0755 "$TMP/$PKG/voidwire-node" /usr/local/bin/voidwire-node
rm -rf "$TMP"
# Cloud VMs sit behind 1:1 NAT: publish the real public address in the URI.
VW_PUB="$(curl -fsS4 --max-time 10 https://api.ipify.org || true)"
printf 'VOIDWIRE_PUBLIC_HOST=%s\n' "$VW_PUB" > /etc/voidwire-node.env
cat > /etc/systemd/system/voidwire-node.service <<'UNIT'
[Unit]
Description=VoidWire RAM-only exit node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/voidwire-node.env
RuntimeDirectory=voidwire
RuntimeDirectoryMode=0700
ExecStart=/usr/local/bin/voidwire-node run {flags}
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/voidwire
LimitCORE=0
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now voidwire-node
for _ in $(seq 1 60); do
  [ -s /run/voidwire/node.uri ] && break
  sleep 1
done
[ -s /run/voidwire/node.uri ] || {{ echo "voidwire-node did not start" >&2; exit 1; }}
"#,
        ver = o.version,
        base = o.release_base,
        flags = node_flags(o),
    )
}

/// Oracle Ubuntu images ship iptables rules that reject everything but SSH.
const ORACLE_IPTABLES: &str = r#"for rule in "-p udp --dport VW_UDP" "-p udp --dport VW_QUIC" "-p tcp --dport VW_TLS"; do
  iptables -C INPUT $rule -j ACCEPT 2>/dev/null || iptables -I INPUT 1 $rule -j ACCEPT
done
iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -j ACCEPT
if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null; fi
"#;

fn oracle_rules(o: &BundleOptions) -> String {
    ORACLE_IPTABLES
        .replace("VW_UDP", &o.udp_port.to_string())
        .replace("VW_QUIC", &o.quic_port.to_string())
        .replace("VW_TLS", &o.tls_port.to_string())
}

fn indent(s: &str, n: usize) -> String {
    let pad = " ".repeat(n);
    s.lines()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("{pad}{l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn cloud_init(o: &BundleOptions, install: &str, oracle: bool) -> String {
    let mut script = String::from(install);
    if oracle {
        script.push_str(&oracle_rules(o));
    }
    script.push_str(
        "echo '=== VoidWire node ready. Import this URI in the VoidWire app: ===' > /dev/console\n\
         voidwire-node uri --state /run/voidwire --qr > /dev/console\n\
         rm -f /var/log/cloud-init-output.log\n",
    );
    let mut out = String::from(
        "#cloud-config\n# Generated by `voidwire cloud generate`. RAM-only VoidWire exit node.\n",
    );
    out.push_str("package_update: true\npackages:\n  - curl\n  - ca-certificates\n  - nftables\n");
    if let Some(k) = &o.ssh_public_key {
        let _ = writeln!(out, "ssh_authorized_keys:\n  - {k}");
    }
    out.push_str("write_files:\n  - path: /usr/local/sbin/voidwire-install.sh\n    permissions: '0700'\n    content: |\n");
    out.push_str(&indent(&format!("#!/bin/bash\n{script}"), 6));
    out.push_str("\nruncmd:\n  - [bash, /usr/local/sbin/voidwire-install.sh]\n  - [shred, -u, /usr/local/sbin/voidwire-install.sh]\n");
    out
}

fn bootstrap_sh(o: &BundleOptions, install: &str, oracle_like: bool) -> String {
    let mut s = String::from(
        "#!/bin/bash\n# Run on a fresh Ubuntu/Debian VPS:\n#   ssh ubuntu@HOST 'sudo bash -s' < bootstrap.sh\n",
    );
    s.push_str("export DEBIAN_FRONTEND=noninteractive\napt-get update -qq && apt-get install -y -qq curl ca-certificates nftables >/dev/null\n");
    s.push_str(install);
    if oracle_like {
        s.push_str("if [ -f /etc/iptables/rules.v4 ]; then\n");
        s.push_str(&indent(&oracle_rules(o), 2));
        s.push_str("\nfi\n");
    }
    s.push_str("voidwire-node uri --state /run/voidwire --qr\n");
    s
}

fn oracle_tf(o: &BundleOptions) -> String {
    let region = o.region.as_deref().unwrap_or("us-ashburn-1");
    format!(
        r#"# OpenTofu / Terraform: Oracle Cloud Always Free VoidWire node.
# Usage: tofu init && tofu apply -var-file=oci.tfvars
terraform {{
  required_providers {{
    oci = {{ source = "oracle/oci", version = ">= 6.0.0" }}
  }}
}}

variable "tenancy_ocid" {{}}
variable "user_ocid" {{}}
variable "fingerprint" {{}}
variable "private_key_path" {{}}
variable "compartment_ocid" {{}}
variable "region" {{ default = "{region}" }}
variable "ssh_public_key" {{ default = "" }}

provider "oci" {{
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}}

data "oci_identity_availability_domains" "ads" {{
  compartment_id = var.tenancy_ocid
}}

data "oci_core_images" "ubuntu_arm" {{
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}}

resource "oci_core_vcn" "vw" {{
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.77.0.0/16"]
  display_name   = "{name}-vcn"
  is_ipv6enabled = true
}}

resource "oci_core_internet_gateway" "vw" {{
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.vw.id
  display_name   = "{name}-igw"
}}

resource "oci_core_route_table" "vw" {{
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.vw.id
  route_rules {{
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.vw.id
  }}
  route_rules {{
    destination       = "::/0"
    network_entity_id = oci_core_internet_gateway.vw.id
  }}
}}

resource "oci_core_security_list" "vw" {{
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.vw.id
  display_name   = "{name}-sl"
  egress_security_rules {{
    destination = "0.0.0.0/0"
    protocol    = "all"
  }}
  egress_security_rules {{
    destination = "::/0"
    protocol    = "all"
  }}
  ingress_security_rules {{
    source   = "0.0.0.0/0"
    protocol = "6"
    tcp_options {{
      min = 22
      max = 22
    }}
  }}
  ingress_security_rules {{
    source   = "0.0.0.0/0"
    protocol = "6"
    tcp_options {{
      min = {tls}
      max = {tls}
    }}
  }}
  ingress_security_rules {{
    source   = "0.0.0.0/0"
    protocol = "17"
    udp_options {{
      min = {udp}
      max = {udp}
    }}
  }}
  ingress_security_rules {{
    source   = "0.0.0.0/0"
    protocol = "17"
    udp_options {{
      min = {quic}
      max = {quic}
    }}
  }}
}}

resource "oci_core_subnet" "vw" {{
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.vw.id
  cidr_block        = "10.77.1.0/24"
  route_table_id    = oci_core_route_table.vw.id
  security_list_ids = [oci_core_security_list.vw.id]
  display_name      = "{name}-subnet"
}}

resource "oci_core_instance" "vw" {{
  compartment_id      = var.compartment_ocid
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  display_name        = "{name}"
  shape               = "VM.Standard.A1.Flex"
  shape_config {{
    ocpus         = 4
    memory_in_gbs = 24
  }}
  source_details {{
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu_arm.images[0].id
    boot_volume_size_in_gbs = 50
  }}
  create_vnic_details {{
    subnet_id        = oci_core_subnet.vw.id
    assign_public_ip = true
  }}
  metadata = {{
    ssh_authorized_keys = var.ssh_public_key
    user_data           = base64encode(file("${{path.module}}/cloud-init.yaml"))
  }}
}}

output "public_ip" {{
  value = oci_core_instance.vw.public_ip
}}

output "next_step" {{
  value = "Wait ~3 minutes, then run: ssh ubuntu@${{oci_core_instance.vw.public_ip}} sudo voidwire-node uri --state /run/voidwire --qr"
}}
"#,
        name = o.node_name,
        udp = o.udp_port,
        tls = o.tls_port,
        quic = o.quic_port,
    )
}

fn gcp_tf(o: &BundleOptions) -> String {
    let region = o.region.as_deref().unwrap_or("us-west1");
    format!(
        r#"# OpenTofu / Terraform: Google Cloud free-tier (e2-micro) VoidWire node.
# Free tier regions: us-west1, us-central1, us-east1. Only 1 GB/month egress is free.
# Usage: tofu init && tofu apply -var project=YOUR_PROJECT_ID
terraform {{
  required_providers {{
    google = {{ source = "hashicorp/google", version = ">= 5.0.0" }}
  }}
}}

variable "project" {{}}
variable "region" {{ default = "{region}" }}
variable "zone" {{ default = "{region}-b" }}
variable "ssh_public_key" {{ default = "" }}

provider "google" {{
  project = var.project
  region  = var.region
}}

resource "google_compute_firewall" "vw" {{
  name    = "{name}-fw"
  network = "default"
  allow {{
    protocol = "udp"
    ports    = ["{udp}", "{quic}"]
  }}
  allow {{
    protocol = "tcp"
    ports    = ["{tls}"]
  }}
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["{name}"]
}}

resource "google_compute_instance" "vw" {{
  name           = "{name}"
  machine_type   = "e2-micro"
  zone           = var.zone
  tags           = ["{name}"]
  can_ip_forward = true
  boot_disk {{
    initialize_params {{
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = 30
      type  = "pd-standard"
    }}
  }}
  network_interface {{
    network = "default"
    access_config {{
      network_tier = "STANDARD"
    }}
  }}
  metadata = {{
    user-data = file("${{path.module}}/cloud-init.yaml")
    ssh-keys  = var.ssh_public_key == "" ? null : "ubuntu:${{var.ssh_public_key}}"
  }}
}}

output "public_ip" {{
  value = google_compute_instance.vw.network_interface[0].access_config[0].nat_ip
}}
"#,
        name = o.node_name,
        udp = o.udp_port,
        tls = o.tls_port,
        quic = o.quic_port,
    )
}

fn dockerfile(o: &BundleOptions) -> String {
    format!(
        r#"# VoidWire node container (RAM-only: run with --read-only and a tmpfs /run).
FROM alpine:3.20
ARG VW_VERSION={ver}
ARG VW_BASE={base}
RUN apk add --no-cache curl ca-certificates nftables iproute2 \
 && ARCH="$(uname -m)" && case "$ARCH" in aarch64|arm64) ARCH=aarch64 ;; *) ARCH=x86_64 ;; esac \
 && PKG="voidwire-node-${{VW_VERSION}}-${{ARCH}}-linux-musl" \
 && curl -fsSL "${{VW_BASE}}/v${{VW_VERSION}}/${{PKG}}.tar.gz" -o /tmp/vw.tgz \
 && curl -fsSL "${{VW_BASE}}/v${{VW_VERSION}}/${{PKG}}.tar.gz.sha256" -o /tmp/vw.sha256 \
 && echo "$(cut -d' ' -f1 /tmp/vw.sha256)  /tmp/vw.tgz" | sha256sum -c - \
 && tar -xzf /tmp/vw.tgz -C /tmp && install -m 0755 /tmp/${{PKG}}/voidwire-node /usr/local/bin/ \
 && rm -rf /tmp/*
ENTRYPOINT ["/usr/local/bin/voidwire-node", "run"]
CMD [{cmd}]
"#,
        ver = o.version,
        base = o.release_base,
        cmd = node_flags(o)
            .split(' ')
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

fn fly_toml(o: &BundleOptions) -> String {
    let region = o.region.as_deref().unwrap_or("fra");
    // Fly delivers UDP only to sockets bound on `fly-global-services`.
    format!(
        r#"# fly.io VoidWire node. Requires a dedicated IPv4: `fly ips allocate-v4`.
app = "{name}"
primary_region = "{region}"

[build]
  dockerfile = "Dockerfile"

[experimental]
  cmd = ["--state", "/run/voidwire", "--ram-only", "--name", "{name}", "--listen-udp", "fly-global-services:{udp}", "--listen-quic", "fly-global-services:{quic}", "--listen-tls", "0.0.0.0:{tls}", "--sni", "{sni}"]

[[services]]
  internal_port = {udp}
  protocol = "udp"
  [[services.ports]]
    port = {udp}

[[services]]
  internal_port = {quic}
  protocol = "udp"
  [[services.ports]]
    port = {quic}

[[services]]
  internal_port = {tls}
  protocol = "tcp"
  [[services.ports]]
    port = {tls}

[[vm]]
  size = "shared-cpu-1x"
  memory = "256mb"
"#,
        name = o.node_name,
        udp = o.udp_port,
        quic = o.quic_port,
        tls = o.tls_port,
        sni = o.sni,
    )
}

fn compose(o: &BundleOptions) -> String {
    format!(
        r#"# docker compose up -d   (any Linux VPS)
services:
  voidwire-node:
    build: .
    image: voidwire-node:{ver}
    network_mode: host
    restart: always
    read_only: true
    cap_add: [NET_ADMIN, NET_RAW, NET_BIND_SERVICE]
    devices: ["/dev/net/tun:/dev/net/tun"]
    tmpfs:
      - /run/voidwire:mode=0700,size=16m
    logging:
      driver: none
    sysctls:
      net.ipv4.ip_forward: "1"
"#,
        ver = o.version
    )
}

fn readme(o: &BundleOptions) -> String {
    let steps = match o.provider {
        Provider::OracleFree => "1. Create an Oracle Cloud account (Always Free) and an API key.\n2. Put tenancy_ocid, user_ocid, fingerprint, private_key_path, compartment_ocid and ssh_public_key in `oci.tfvars`.\n3. `tofu init && tofu apply -var-file=oci.tfvars` (Terraform works too).\n   If A1 capacity is exhausted in your region, retry later or pick another availability domain.\n4. After ~3 minutes: `ssh ubuntu@<public_ip> sudo voidwire-node uri --state /run/voidwire --qr` and import the URI in VoidWire.\n\nNo Terraform? Paste `cloud-init.yaml` into the \"Cloud-init script\" box when creating an Ampere A1 Ubuntu 24.04 instance in the console, and open UDP and TCP ports in the subnet's security list.",
        Provider::GcpFree => "1. `gcloud auth application-default login`\n2. `tofu init && tofu apply -var project=YOUR_PROJECT`\n3. `gcloud compute ssh voidwire-node -- sudo voidwire-node uri --state /run/voidwire --qr`",
        Provider::Fly => "1. `fly launch --no-deploy --copy-config`\n2. `fly ips allocate-v4` (UDP needs a dedicated IPv4)\n3. `fly deploy`\n4. `fly ssh console -C 'voidwire-node uri --state /run/voidwire --qr'`",
        Provider::Docker => "1. Copy this folder to the VPS.\n2. `docker compose up -d --build`\n3. `docker compose exec voidwire-node voidwire-node uri --state /run/voidwire --qr`",
        Provider::Ssh => "1. `ssh root@HOST 'bash -s' < bootstrap.sh`\n2. The script prints the node URI and QR code when it finishes.",
    };
    format!(
        "# VoidWire node: {provider:?}\n\n{cost}\n\n## Deploy\n\n{steps}\n\n## RAM-only guarantees\n\nState lives in `/run/voidwire` (tmpfs). Swap is disabled and masked, journald stores nothing, rsyslog is disabled and core dumps are off. Rebooting the server wipes the node identity and every session; import the new URI afterwards.\n\nThe node signs a runtime attestation (`voidwire status --audit` shows it) covering swap, logging, RAM-only mode, its binary hash and uptime. This is evidence that the operator configured it honestly, not proof: whoever controls the server can always lie.\n",
        provider = o.provider,
        cost = o.provider.cost_note(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(p: Provider) -> BundleOptions {
        let mut o = BundleOptions::new(p, "v0.1.0");
        o.owner_wg_public_key = Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".into());
        o.ssh_public_key = Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@host".into());
        o
    }

    #[test]
    fn oracle_bundle_is_ram_only_and_free_shape() {
        let b = generate_bundle(&opts(Provider::OracleFree)).unwrap();
        let ci = b.get("cloud-init.yaml").unwrap();
        assert!(ci.starts_with("#cloud-config"));
        for needle in [
            "swapoff -a",
            "Storage=none",
            "tcp_congestion_control=bbr",
            "sha256sum -c",
            "--ram-only",
            "--authorize bmXOC",
            "iptables -I INPUT 1",
            "RuntimeDirectory=voidwire",
            "VOIDWIRE_PUBLIC_HOST",
        ] {
            assert!(ci.contains(needle), "missing {needle}");
        }
        let tf = b.get("main.tf").unwrap();
        assert!(tf.contains("VM.Standard.A1.Flex"));
        assert!(tf.contains("ocpus         = 4"));
        assert!(tf.contains("memory_in_gbs = 24"));
        assert!(b.get("bootstrap.sh").unwrap().starts_with("#!/bin/bash"));
        assert!(b.get("README.md").unwrap().contains("10 TB"));
    }

    #[test]
    fn gcp_uses_free_machine_and_warns_about_egress() {
        let b = generate_bundle(&opts(Provider::GcpFree)).unwrap();
        assert!(b.get("main.tf").unwrap().contains("e2-micro"));
        assert!(b.get("README.md").unwrap().contains("1 GB/month"));
    }

    #[test]
    fn fly_binds_global_services() {
        let b = generate_bundle(&opts(Provider::Fly)).unwrap();
        assert!(b
            .get("fly.toml")
            .unwrap()
            .contains("fly-global-services:51820"));
        assert!(b.get("Dockerfile").unwrap().contains("sha256sum -c"));
    }

    #[test]
    fn rejects_injection() {
        let mut o = opts(Provider::Ssh);
        o.node_name = "x; rm -rf /".into();
        assert!(generate_bundle(&o).is_err());
        let mut o = opts(Provider::Ssh);
        o.release_base = "https://evil.example/$(id)".into();
        assert!(generate_bundle(&o).is_err());
        let mut o = opts(Provider::Ssh);
        o.ssh_public_key = Some("ssh-ed25519 AAAA\nruncmd: [reboot]".into());
        assert!(generate_bundle(&o).is_err());
        assert!(Provider::parse("aws-free").is_err());
    }

    #[test]
    fn cloud_init_is_valid_yaml_shape() {
        let b = generate_bundle(&opts(Provider::OracleFree)).unwrap();
        let ci = b.get("cloud-init.yaml").unwrap();
        // Every line of the embedded script must be indented under `content: |`.
        let mut in_block = false;
        for line in ci.lines() {
            if line.ends_with("content: |") {
                in_block = true;
                continue;
            }
            if in_block {
                if line.starts_with("runcmd:") {
                    in_block = false;
                    continue;
                }
                assert!(
                    line.is_empty() || line.starts_with("      "),
                    "bad indent: {line}"
                );
            }
        }
    }

    #[test]
    fn writes_files() {
        let dir = std::env::temp_dir().join(format!("vw-bundle-{}", std::process::id()));
        let b = generate_bundle(&opts(Provider::Docker)).unwrap();
        let written = b.write_to(&dir).unwrap();
        assert_eq!(written.len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
