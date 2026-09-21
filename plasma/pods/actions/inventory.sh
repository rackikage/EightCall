#!/usr/bin/env bash
# actions/inventory.sh — passive inventory: reverse DNS + ARP table MAC +
# (optional) TCP probes for service banners. No active probing of unknown
# services: this is a read-only view of what's already advertising.
#
# Pod contract:
#     args: $1 = alias, $2 = ip
#     exit: always 0 (inventory is best-effort)
#     stdout: a short label that lands in the run record

TARGET="${1:---}"
IP="${2:---}"

# Reverse DNS (best-effort).
HOST=""
if command -v host >/dev/null 2>&1; then
    HOST=$(host "$IP" 2>/dev/null | awk '/domain name pointer/ {print $5; exit}' | sed 's/\.$//')
elif command -v dig >/dev/null 2>&1; then
    HOST=$(dig +short -x "$IP" 2>/dev/null | sed 's/\.$//' | head -1)
fi
[ -n "$HOST" ] || HOST="unknown"

# ARP neighbor table (best-effort, only useful on the same L2 segment).
MAC=""
if command -v arp >/dev/null 2>&1; then
    MAC=$(arp -n "$IP" 2>/dev/null | awk 'NR>1 && $1==ip {print $3; exit}' ip="$IP")
fi
[ -n "$MAC" ] || MAC="unknown"

echo "inventory $TARGET ($IP) host=$HOST mac=$MAC"

exit 0