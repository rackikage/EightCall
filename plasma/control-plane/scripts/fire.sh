#!/bin/sh
# Stop ONLY this project's process. No global pkill.
set -eu

cd "$(dirname "$0")/.."
PORT="${PORT:-8787}"
LOGDIR="data/logs"
mkdir -p "$LOGDIR"

killed=0

# 1) pid file, if present, verified to be this project's node process
if [ -f data/run/nest.pid ]; then
  PID="$(cat data/run/nest.pid 2>/dev/null || true)"
  if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
    CMD="$(ps -o command= -p "$PID" 2>/dev/null || true)"
    case "$CMD" in
      *dist/main.js*)
        kill "$PID" 2>/dev/null && killed=1 && echo "killed pid $PID (pidfile)" ;;
      *) echo "pidfile pid $PID is not this project; ignoring" ;;
    esac
  fi
  rm -f data/run/nest.pid
fi

# 2) whatever is listening on our port, verified by command line
PIDS="$(lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)"
for p in $PIDS; do
  CMD="$(ps -o command= -p "$p" 2>/dev/null || true)"
  case "$CMD" in
    *dist/main.js*)
      kill "$p" 2>/dev/null && killed=1 && echo "killed pid $p (port $PORT)" ;;
    *) echo "port $PORT held by unrelated pid $p; not touching it" ;;
  esac
done

# 3) verify nothing of ours is left and the port is clear
sleep 1
LEFT="$(lsof -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)"
if [ -n "$LEFT" ]; then
  echo "WARN: port $PORT still held by: $LEFT"
  exit 1
fi
echo "port $PORT clear; plasma processes stopped (killed=$killed)"
