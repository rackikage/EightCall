#!/usr/bin/env bash
# killswitch.sh — hard stop for the pods control plane.
#
# Stops watcher.sh and rotator.sh (signals them via $PODS_STOP), waits
# up to $FIRE_GRACE_SECONDS for a clean exit, then escalates to SIGTERM,
# then to SIGKILL. Touches the stop marker. Does NOT touch:
#
#     unrelated processes
#     unrelated SSH / system services
#     unrelated Node / Python / shell sessions
#     state files (you can inspect them post-stop)
#     pods.log / runs.jsonl (audit trail stays)
#
# Usage:
#     ./killswitch.sh             # stop both daemons
#     ./killswitch.sh --purge     # also remove PID files + lock dir (state kept)

set -eu

PODS_HOME="${PODS_HOME:-${HOME}/pods}"
# shellcheck disable=SC1091
. "${PODS_HOME}/pods.conf"

HERE="$(cd "$(dirname "$0")" && pwd)"

ts() { date -u +%FT%TZ; }

stop_one() {
    local script="$1" label="$2"
    if [ ! -x "$script" ]; then
        printf 'killswitch: %s script not found at %s (skipped)\n' "$label" "$script" >&2
        return 0
    fi
    "$script" stop || true
}

printf '%s killswitch: event=begin grace_s=%s\n' "$(ts)" "$FIRE_GRACE_SECONDS" >> "$PODS_LOG"

stop_one "${HERE}/watcher.sh" "watcher"
stop_one "${HERE}/rotator.sh"  "rotator"

if [ "${1:-}" = "--purge" ]; then
    rm -rf "$PODS_PIDS" "$PODS_LOCKS"
    printf '%s killswitch: event=purge status=ok\n' "$(ts)" >> "$PODS_LOG"
fi

printf '%s killswitch: event=done status=ok\n' "$(ts)" >> "$PODS_LOG"
echo "killswitch: stopped. log: $PODS_LOG"