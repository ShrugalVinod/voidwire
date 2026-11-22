#!/bin/sh
# Public observer at 203.0.113.99: answers UDP/TCP so leaks would succeed,
# and records everything it receives.
set -eu
(while true; do nc -lu -p 9999 -w 1 >/dev/null 2>&1; done) &
(while true; do nc -l -p 8080 >/dev/null 2>&1; done) &
exec tcpdump -i any -nn -U -w /captures/observer.pcap "host 203.0.113.99"
