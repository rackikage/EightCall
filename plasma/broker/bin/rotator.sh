#!/data/data/com.termux/files/usr/bin/bash
# rotator.sh — B: dispatch loop. Never writes authority state.
#
# For each enabled enrollment it ASKS the controller for a lease. A denial
# (not granted / lease held / revoked / policy mismatch) is the normal path and
# means "do nothing". A grant returns a single-use token, which is handed to
# pod.sh (C). B holds no keys, no database handle, and no authority of its own.
set -Eeuo pipefail
PATH='/data/data/com.termux/files/usr/bin:/usr/bin:/bin:/system/bin'
umask 077

ACB="${BROKER_BIN:-$HOME/projects/broker/bin/broker}"
ACTION="${ROTATE_ACTION:-inventory}"
INTERVAL="${ROTATE_INTERVAL_SECONDS:-30}"
STOP="${BROKER_HOME:-$HOME/data/broker}/.stop"
ONESHOT="${1:-}"

cycle() {
    "$ACB" pods 2>/dev/null | awk -F'\t' '$3=="enabled"{print $2}' | while read -r t; do
        token="$("$ACB" lease --target "$t" --action "$ACTION" \
                   --owner "rotator@$(hostname)" --token-only 2>/dev/null)" || continue
        [ -n "$token" ] || continue
        "$HOME/projects/broker/bin/pod.sh" "$token" "$t" "$ACTION" >/dev/null 2>&1 || true
    done
}

if [ "$ONESHOT" = "--once" ]; then
    cycle
    exit 0
fi

echo "rotator: start action=${ACTION} interval=${INTERVAL}s pid=$$"
while [ ! -f "$STOP" ]; do
    cycle
    sleep "$INTERVAL"
done
echo "rotator: stop flag seen, exiting"
