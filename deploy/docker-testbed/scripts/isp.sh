#!/bin/sh
# ISP router: NATs the home network to the "internet" and records every packet
# that crosses the subscriber link (eth_isp) for leak analysis.
set -eu
ISP_IF=$(ip -o -4 addr show | awk '/198\.51\.100\.1\//{print $2}')
ip link set "$ISP_IF" name eth_isp 2>/dev/null || true
ip route replace 192.168.77.0/24 via 198.51.100.2
nft -f - <<NFT
table ip nat { chain post { type nat hook postrouting priority 100; oifname != "eth_isp" masquerade; } }
NFT
exec tcpdump -i any -nn -U -w /captures/eth_isp.pcap "net 198.51.100.0/24"
