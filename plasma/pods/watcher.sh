#!/usr/bin/env bash
# watcher.sh — A: every W seconds, scan owned targets and emit triggers
# when liveness changes.
#
# This is a long-running daemon. Start with:
#     ./watcher.sh start     # forks, writes pids/watcher.pid, returns
#     ./watcher.sh stop      # touches .stop, waits up to grace seconds
#     ./watcher.sh status    # prints pid + alive/last-scan age
#     ./watcher.sh foreground # run in the current shell (for debugging)
#
# State files (atomic, written via mktemp+mv):
#     state/state.tsv       alias\tip\tstatus\tlast_change_epoch
#     state/triggers.tsv    alias\tevent\tat_epoch   (append-only, read by B)
#
# The watcher NEVER invokes pods — that's B's job. It only maintains the
# target-liveness state file and an append-only trigger log.

set -eu

PODS_HOME="${PODS_HOME:-${HOME}/pods}"
# shellcheck disable=SC1091
. "${PODS_HOME}/pods.conf"

ts() { date -u +%FT%TZ; }
now() { date +%s; }

mkdir -p "$PODS_STATE" "$PODS_PIDS" "$PODS_LOCKS"
: > "$PODS_LOCKS/.mkdir-ok" 2>/dev/null || true

STATE="$PODS_STATE/state.tsv"
TRIGGERS="$PODS_STATE/triggers.tsv"
PIDFILE="$PODS_PIDS/watcher.pid"

# Initialize state.tsv from targets.conf on first run.
if [ ! -f "$STATE" ]; then
    awk -F= '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        { gsub(/[[:space:]]/, "", $2); printf "%s\t%s\tUNKNOWN\t0\n", $1, $2 }
    ' "$PODS_TARGETS" > "${STATE}.init"
    mv -f "${STATE}.init" "$STATE"
fi

# ----- daemon control ----------------------------------------------------

is_alive() {
    [ -f "$PIDFILE" ] || return 1
    local pid
    pid=$(cat "$PIDFILE" 2>/dev/null || echo "")
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

atomic_write() {  # atomic_write <path> <stdin>
    local target="$1"
    local tmp
    tmp=$(mktemp "${target}.XXXXXX")
    cat > "$tmp"
    mv -f "$tmp" "$target"
}

scan_once() {
    local new tmp alias ip last_status now_status at
    at=$(now)
    new=$(mktemp "${STATE}.new.XXXXXX")
    : > "$new"

    while IFS='=' read -r alias ip _; do
        case "$alias" in
            ''|\#*) continue ;;
        esac
        ip=$(printf '%s' "$ip" | tr -d ' \t')
        last_status=$(awk -F'\t' -v a="$alias" '$1==a {print $3; exit}' "$STATE" 2>/dev/null || echo "UNKNOWN")

        if ping -c "$PING_COUNT" -W "$PING_TIMEOUT_SECONDS" "$ip" >/dev/null 2>&1; then
            now_status="UP"
        else
            now_status="DOWN"
        fi

        printf '%s\t%s\t%s\t%s\n' "$alias" "$ip" "$now_status" "$at" >> "$new"

        if [ "$last_status" != "$now_status" ] && [ "$last_status" != "UNKNOWN" ]; then
            # State changed -> emit a trigger. B picks these up from $TRIGGERS.
            printf '%s\t%s_to_%s\t%s\n' "$alias" "$last_status" "$now_status" "$at" >> "$TRIGGERS"
            printf '%s stage=A event=trigger target=%s ip=%s from=%s to=%s status=ok\n' \
                "$(ts)" "$alias" "$ip" "$last_status" "$now_status" >> "$PODS_LOG"
        fi
    done < "$PODS_TARGETS"

    mv -f "$new" "$STATE"
}

run_loop() {
    # Trap signals for clean exit. Touching $PODS_STOP also exits cleanly.
    trap '[ -e "$PODS_STOP" ] || exit 0; exit 0' INT TERM
    echo "$$" > "$PIDFILE"
    printf '%s stage=A event=started pid=%s interval_s=%s status=ok\n' \
        "$(ts)" "$$" "$WATCH_INTERVAL_SECONDS" >> "$PODS_LOG"

    while true; do
        [ -e "$PODS_STOP" ] && break
        scan_once || {
            printf '%s stage=A event=scan_error status=fail\n' "$(ts)" >> "$PODS_LOG"
        }
        # Sleep in small chunks so .stop is honored within a few seconds, not
        # a full WATCH_INTERVAL_SECONDS.
        slept=0
        while [ "$slept" -lt "$WATCH_INTERVAL_SECONDS" ]; do
            [ -e "$PODS_STOP" ] && break 2
            sleep 1
            slept=$((slept + 1))
        done
    done

    printf '%s stage=A event=stopped pid=%s status=ok\n' "$(ts)" "$$" >> "$PODS_LOG"
    rm -f "$PIDFILE"
}

case "${1:-foreground}" in
    start)
        if is_alive; then
            echo "watcher: already running (pid=$(cat "$PIDFILE"))" >&2
            exit 0
        fi
        # Foreground shell exits; child continues via nohup + redirected FDs.
        # setsid is intentionally NOT used (it is not on macOS by default).
        nohup "$0" foreground </dev/null >>"$PODS_LOG" 2>&1 &
        disown 2>/dev/null || true
        sleep 0.2
        is_alive && echo "watcher: started (pid=$(cat "$PIDFILE"))" || {
            echo "watcher: failed to start" >&2
            exit 1
        }
        ;;
    stop)
        touch "$PODS_STOP"
        if is_alive; then
            for _ in $(seq 1 "$FIRE_GRACE_SECONDS"); do
                is_alive || break
                sleep 1
            done
            is_alive && kill -TERM "$(cat "$PIDFILE")" 2>/dev/null || true
        fi
        rm -f "$PODS_STOP" "$PIDFILE"
        ;;
    status)
        if is_alive; then
            age=$(( $(now) - $(stat -f %m "$STATE" 2>/dev/null || stat -c %Y "$STATE" 2>/dev/null || echo 0) ))
            echo "watcher: alive pid=$(cat "$PIDFILE") last_scan_age_s=${age:-?}"
        else
            echo "watcher: not running"
            exit 1
        fi
        ;;
    foreground|"")
        run_loop
        ;;
    *)
        echo "usage: $0 {start|stop|status|foreground}" >&2
        exit 64
        ;;
esac