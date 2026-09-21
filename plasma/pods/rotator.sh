#!/usr/bin/env bash
# rotator.sh — B: read triggers from A, pick an eligible target, dispatch
# a pod.
#
# Daemon control (mirrors watcher.sh):
#     ./rotator.sh start      # forks, writes pids/rotator.pid, returns
#     ./rotator.sh stop       # touches .stop, waits up to grace seconds
#     ./rotator.sh status     # prints pid + processed_trigger_count
#     ./rotator.sh foreground # run in the current shell (for debugging)
#
# What B does, in order, every $ROTATE_INTERVAL_SECONDS:
#     1. Read all unread rows from $TRIGGERS.
#     2. For each trigger, find an eligible target (UP and not in cooldown).
#     3. Dispatch pod.sh against that target.
#     4. Append the trigger's key to $PROCESSED so it isn't re-run.
#
# B never re-dispatches the same trigger twice: once appended to $PROCESSED
# it is permanent. (If you delete $PROCESSED you replay — that is a feature,
# not a bug, for an idempotent retry tool.)

set -eu

PODS_HOME="${PODS_HOME:-${HOME}/pods}"
# shellcheck disable=SC1091
. "${PODS_HOME}/pods.conf"

ts() { date -u +%FT%TZ; }
now() { date +%s; }

mkdir -p "$PODS_STATE" "$PODS_PIDS" "$PODS_LOCKS"

# shellcheck disable=SC1091
. "${PODS_HOME}/lib_eligibility.sh"

STATE="$PODS_STATE/state.tsv"
TRIGGERS="$PODS_STATE/triggers.tsv"
PROCESSED="$PODS_STATE/processed.tsv"
LASTDISP="$PODS_STATE/last_dispatch.tsv"
PIDFILE="$PODS_PIDS/rotator.pid"

: > "$PODS_LOCKS/.mkdir-ok" 2>/dev/null || true
[ -f "$PROCESSED" ] || : > "$PROCESSED"
[ -f "$LASTDISP" ] || : > "$LASTDISP"

# A trigger is uniquely identified by "<alias>\t<event>\t<at>" — the at is
# the epoch second of the change, supplied by A. Two scanners running on
# the same alias at the same second produce the same trigger; dedupe is
# intentional.
trigger_key() { printf '%s\n' "$1"; }

already_processed() {
    # $1 = trigger key (alias TAB event TAB at)
    grep -F -m1 -x -- "$1" "$PROCESSED" >/dev/null 2>&1
}

mark_processed() { printf '%s\n' "$1" >> "$PROCESSED"; }

# Dispatch one trigger. $1 = trigger key (alias<TAB>event<TAB>at).
dispatch_trigger() {
    local key="$1" alias event at action rc port
    alias=$(printf '%s' "$key" | awk -F'\t' '{print $1}')
    event=$(printf '%s' "$key" | awk -F'\t' '{print $2}')
    at=$(printf '%s' "$key" | awk -F'\t' '{print $3}')

    if already_processed "$key"; then
        return 0
    fi

    if ! eligible "$alias"; then
        # Either the target isn't UP right now, or it's in cooldown. Log
        # the skip and mark processed so we don't keep retrying the same
        # stale trigger on every loop iteration.
        printf '%s stage=B event=skip trigger_target=%s reason=ineligible status=ok\n' \
            "$(ts)" "$alias" >> "$PODS_LOG"
        mark_processed "$key"
        return 0
    fi

    # Action selection. Default is whatever $ACTION_DEFAULT names; future
    # rotations will add other modes here (nat-map, route-inspect, ...).
    action="${ACTION_DEFAULT:-health}"

    HOP="${HOP:-0}"
    CHAIN_ID="${CHAIN_ID:-${CHAIN_PREFIX}-$(date +%s)}"
    EXEC_ID="E$(printf '%08x' "$$" "$RANDOM")"
    export HOP CHAIN_ID EXEC_ID

    printf '%s stage=B event=rotate target=%s trigger=%s action=%s status=ok\n' \
        "$(ts)" "$alias" "$event" "$action" >> "$PODS_LOG"

    set +e
    "${PODS_HOME}/pod.sh" "$alias" "$action"
    rc=$?
    set -e

    printf '%s\t%s\n' "$alias" "$(now)" >> "$LASTDISP"

    printf '%s stage=B event=commit target=%s action=%s rc=%d status=%s\n' \
        "$(ts)" "$alias" "$action" "$rc" "$([ "$rc" -eq 0 ] && echo ok || echo fail)" >> "$PODS_LOG"

    mark_processed "$key"
}

# Read all triggers, dispatch each new one. Triggers file grows
# append-only; we don't truncate it so re-runs replay exactly once
# (idempotent on $PROCESSED).
process_triggers() {
    [ -s "$TRIGGERS" ] || return 0
    while IFS= read -r key; do
        [ -n "$key" ] || continue
        dispatch_trigger "$key"
    done < "$TRIGGERS"
}

is_alive() {
    [ -f "$PIDFILE" ] || return 1
    local pid
    pid=$(cat "$PIDFILE" 2>/dev/null || echo "")
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

run_loop() {
    trap '[ -e "$PODS_STOP" ] || exit 0; exit 0' INT TERM
    echo "$$" > "$PIDFILE"
    printf '%s stage=B event=started pid=%s interval_s=%s cooldown_s=%s status=ok\n' \
        "$(ts)" "$$" "$ROTATE_INTERVAL_SECONDS" "$COOLDOWN_SECONDS" >> "$PODS_LOG"

    while true; do
        [ -e "$PODS_STOP" ] && break
        process_triggers || {
            printf '%s stage=B event=loop_error status=fail\n' "$(ts)" >> "$PODS_LOG"
        }
        slept=0
        while [ "$slept" -lt "$ROTATE_INTERVAL_SECONDS" ]; do
            [ -e "$PODS_STOP" ] && break 2
            sleep 1
            slept=$((slept + 1))
        done
    done

    printf '%s stage=B event=stopped pid=%s status=ok\n' "$(ts)" "$$" >> "$PODS_LOG"
    rm -f "$PIDFILE"
}

case "${1:-foreground}" in
    start)
        if is_alive; then
            echo "rotator: already running (pid=$(cat "$PIDFILE"))" >&2
            exit 0
        fi
        # Foreground shell exits; child continues via nohup + redirected FDs.
        # setsid is intentionally NOT used (it is not on macOS by default).
        nohup "$0" foreground </dev/null >>"$PODS_LOG" 2>&1 &
        disown 2>/dev/null || true
        sleep 0.2
        is_alive && echo "rotator: started (pid=$(cat "$PIDFILE"))" || {
            echo "rotator: failed to start" >&2
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
            count=$(wc -l < "$PROCESSED" 2>/dev/null | tr -d ' ' || echo 0)
            echo "rotator: alive pid=$(cat "$PIDFILE") processed_triggers=${count:-0}"
        else
            echo "rotator: not running"
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