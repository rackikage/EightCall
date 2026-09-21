#!/usr/bin/env bash
# state-receiver.sh — start/stop/status wrapper for state_receiver.py.
#
# Inbound-only HTTP endpoint for the pods architecture: iPhone-side
# agents (and any other owned node) dial back to POST their state.
# The endpoint lives at PODS_RECEIVER_HOST:PODS_RECEIVER_PORT
# (defaults: 127.0.0.1:41800 — loopback only; state_receiver.py binds
# PODS_RECEIVER_HOST which defaults to 127.0.0.1). Reach it from an owned
# node over an explicit loopback forward, never by binding a LAN interface.
#
# Daemon control (mirrors watcher.sh / rotator.sh):
#     ./state-receiver.sh start      # forks, writes pids/state-receiver.pid
#     ./state-receiver.sh stop       # touches .stop, waits up to grace seconds
#     ./state-receiver.sh status     # prints pid + uptime + port
#     ./state-receiver.sh foreground # run in the current shell (debugging)
#
# state-receiver is NOT inside killswitch.sh — it's a separate concern from A/B/C.
# `killswitch.sh` stops A and B (and clears their state). state-receiver keeps
# running. Stop it explicitly if you want the inbound endpoint closed.

set -eu

PODS_HOME="${PODS_HOME:-${HOME}/pods}"
# shellcheck disable=SC1091
. "${PODS_HOME}/pods.conf"

ts() { date -u +%FT%TZ; }
now() { date +%s; }

mkdir -p "$PODS_PIDS" "$PODS_LOCKS"
PIDFILE="$PODS_PIDS/state-receiver.pid"
LOG="${RECEIVER_LOG:-${PODS_LOG}}"

is_alive() {
    [ -f "$PIDFILE" ] || return 1
    local pid
    pid=$(cat "$PIDFILE" 2>/dev/null || echo "")
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

run_loop() {
    trap 'exit 0' INT TERM
    PYTHONUNBUFFERED=1 PODS_LOG="$LOG" "${PODS_HOME}/state_receiver.py" &
    CPID=$!
    wait "$CPID" || true
    printf '%s stage=D event=stopped status=ok\n' "$(ts)" >> "$LOG"
}

case "${1:-foreground}" in
    start)
        if is_alive; then
            echo "state-receiver: already running (pid=$(cat "$PIDFILE"))" >&2
            exit 0
        fi
        nohup "$0" foreground </dev/null >>"$LOG" 2>&1 &
        disown 2>/dev/null || true
        # Give Python time to import + bind. macOS Python 3 cold-start
        # + socket bind is closer to 1.5s than 300ms.
        sleep 2
        is_alive && echo "state-receiver: started (pid=$(cat "$PIDFILE"))" || {
            echo "state-receiver: failed to start" >&2
            exit 1
        }
        ;;
    stop)
        if is_alive; then
            pid=$(cat "$PIDFILE")
            kill -TERM "$pid" 2>/dev/null || true
            for _ in $(seq 1 "${FIRE_GRACE_SECONDS:-10}"); do
                is_alive || break
                sleep 1
            done
            is_alive && kill -KILL "$pid" 2>/dev/null || true
        fi
        rm -f "$PIDFILE"
        ;;
    status)
        if is_alive; then
            age=$(( $(now) - $(stat -f %m "$PIDFILE" 2>/dev/null || stat -c %Y "$PIDFILE" 2>/dev/null || echo 0) ))
            echo "state-receiver: alive pid=$(cat "$PIDFILE") age_s=$age port=${PODS_RECEIVER_PORT:-41800}"
        else
            echo "state-receiver: not running"
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