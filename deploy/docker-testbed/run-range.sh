#!/bin/bash
# Runs the adversarial range end to end and fails if any cleartext packet from
# the client reaches the ISP link or the observer.
set -euo pipefail
cd "$(dirname "$0")"
rm -f captures/*.pcap
docker compose up -d --build
NODE_URI=""
for _ in $(seq 1 90); do
  NODE_URI=$(docker compose exec -T node voidwire-node uri --state /run/voidwire 2>/dev/null || true)
  [ -n "$NODE_URI" ] && break; sleep 1
done
[ -n "$NODE_URI" ] || { echo "node did not publish a URI"; exit 1; }
docker compose exec -T client voidwire nodes import "$NODE_URI"
docker compose exec -T client voidwire up --profile stealth
docker compose exec -T client voidwire status --audit

echo "[1] SIGKILL race"
docker compose exec -T -d client sh -c 'while true; do echo leak | nc -u -w0 203.0.113.99 9999; nc -z -w1 203.0.113.99 8080; done'
sleep 3; docker compose exec -T client pkill -9 voidwired; sleep 5
echo "[2] Tunnelvision: rogue DHCP routes"
docker compose exec -T client sh -c 'ip route add 1.0.0.0/8 via 192.168.77.66 || true; ip route add 203.0.113.0/24 via 192.168.77.66 || true'
sleep 3
echo "[3] Hardcoded DNS"
docker compose exec -T client sh -c 'nc -u -w1 8.8.8.8 53 </dev/null; nc -z -w1 1.1.1.1 853; true'
echo "[5] IPv6 egress"
docker compose exec -T client sh -c 'nc -6 -u -w1 2001:4860:4860::8888 53 </dev/null; true'
sleep 2
docker compose stop isp observer
LEAKS_ISP=$(docker run --rm -v "$PWD/captures:/c" voidwire-range-isp tshark -r /c/eth_isp.pcap -Y 'ip.dst==203.0.113.99 || ip.dst==8.8.8.8 || dns || ipv6' 2>/dev/null | wc -l)
LEAKS_OBS=$(docker run --rm -v "$PWD/captures:/c" voidwire-range-isp tshark -r /c/observer.pcap -Y 'ip.src!=203.0.113.10 && ip.dst==203.0.113.99' 2>/dev/null | wc -l)
docker compose down
echo "cleartext packets on eth_isp: $LEAKS_ISP, at observer: $LEAKS_OBS"
[ "$LEAKS_ISP" -eq 0 ] && [ "$LEAKS_OBS" -eq 0 ] && echo "RANGE PASSED: 0 leaks" || { echo "RANGE FAILED"; exit 1; }
