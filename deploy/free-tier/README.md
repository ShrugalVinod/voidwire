# Free-tier node deployment

Generate a fresh, hardened bundle for your provider with the CLI (recommended,
it embeds your version and optional owner key):

```bash
voidwire cloud generate --provider oracle-free --out ./my-node
```

Providers: `oracle-free` (best: 4 OCPU / 24 GB Ampere A1 and 10 TB/month egress at $0),
`gcp-free` (e2-micro, but only 1 GB/month free egress), `fly` (not free for new
accounts), `docker`, `ssh`. Every bundle runs `voidwire-node` RAM-only: state in
tmpfs, swap off, journald `Storage=none`, BBR, all transports enabled.

The release workflow also copies this folder into each
`voidwire-node-*-linux-musl.tar.gz` so it travels with the binary.
