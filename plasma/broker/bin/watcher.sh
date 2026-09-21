#!/data/data/com.termux/files/usr/bin/bash
# watcher.sh — A: observer only.
#
# Writes observations (reachability) for enrolled targets. It NEVER dispatches,
# never enrolls, never touches authority state. Discovery != enrollment.
set -Eeuo pipefail
PATH='/data/data/com.termux/files/usr/bin:/usr/bin:/bin:/system/bin'
umask 077

ACB="${BROKER_BIN:-$HOME/projects/broker/bin/broker}"
INTERVAL="${WATCH_INTERVAL_SECONDS:-60}"
STOP="${BROKER_HOME:-$HOME/data/broker}/.stop"
ONESHOT="${1:-}"

scan() {
    "$ACB" pods 2>/dev/null | awk -F'\t' '$3=="enabled"{print $2}' | while read -r t; do
        "$ACB" observe --target "$t" >/dev/null 2>&1 || true
    done
}

if [ "$ONESHOT" = "--once" ]; then
    scan
    exit 0
fi

echo "watcher: start interval=${INTERVAL}s pid=$$"
while [ ! -f "$STOP" ]; do
    scan
    sleep "$INTERVAL"
done
echo "watcher: stop flag seen, exiting"
