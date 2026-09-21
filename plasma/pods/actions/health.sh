#!/usr/bin/env bash
# actions/health.sh — ICMP liveness probe for one target.
#
# Pod contract:
#     args: $1 = alias, $2 = ip
#     exit: 0 = reachable, non-zero = unreachable
#     stdout/stderr: silent on success, short reason on failure.

set -eu

TARGET="${1:-?}"
IP="${2:-?}"

if ping -c "${PING_COUNT:-1}" -W "${PING_TIMEOUT_SECONDS:-2}" "$IP" >/dev/null 2>&1; then
    exit 0
fi
echo "ping failed: $TARGET ($IP)" >&2
exit 1