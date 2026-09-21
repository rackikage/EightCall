#!/usr/bin/env bash
# actions/probe.sh — TCP-port reachability sweep against one target.
#
# Pod contract:
#     args: $1 = alias, $2 = ip
#     exit: 0 if at least one probe responded, 1 if none did
#     stdout: one "ip:port=open|closed" line per port (printed for the log;
#             pod.sh captures nothing from the action, so this is advisory)
#
# Ports come from $PROBE_TARGETS, populated from $PROBE_PORTS (csv) in pods.conf.
# Useful iOS-adjacent defaults: 5353 (mDNS), 62078 (iOS lockdown, requires
# pairing), 8443 (often MDM).

set -eu

TARGET="${1:-?}"
IP="${2:-?}"
PROBE_TARGETS="${PROBE_TARGETS:-80 443 5353 8080 8443 62078}"

opens=""
closed=""
for port in $PROBE_TARGETS; do
    # /dev/tcp is a bash builtin that opens (or fails) without nc/nmap.
    if (exec 3<>/dev/tcp/"$IP"/"$port") 2>/dev/null; then
        exec 3<&- 3>&-
        opens="$opens $port"
    else
        closed="$closed $port"
    fi
done

echo "probe $TARGET ($IP): open=[${opens:-none}] closed=[${closed:-none}]"

if [ -n "$opens" ]; then
    exit 0
fi
exit 1