#!/bin/sh
# Home router + DPI box: forwards the LAN upstream but drops any UDP datagram
# carrying a standard WireGuard handshake initiation (type 0x01000000, 148 B),
# the way censoring middleboxes fingerprint WireGuard.
set -eu
ip route replace default via 198.51.100.1
nft -f - <<'NFT'
table inet dpi {
  chain fwd {
    type filter hook forward priority 0; policy accept;
    udp length 156 @th,64,32 0x01000000 counter drop comment "plain WireGuard handshake"
  }
}
table ip nat { chain post { type nat hook postrouting priority 100; ip saddr 192.168.77.0/24 masquerade; } }
NFT
exec sleep infinity
