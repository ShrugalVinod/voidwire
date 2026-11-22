#!/bin/sh
# Locked-down client: installs routes like a home user, starts voidwired,
# imports the exit node and connects.
set -eu
ip route replace default via 192.168.77.1
mkdir -p "$VOIDWIRE_STATE_DIR"
voidwired run &
sleep_until() { for _ in $(seq 1 60); do "$@" && return 0; sleep 1; done; return 1; }
sleep_until test -S /var/run/voidwire/voidwired.sock
exec sleep infinity
