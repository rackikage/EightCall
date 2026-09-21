#!/data/data/com.termux/files/usr/bin/bash
# pod.sh — C: one-shot runner. This is the only way an action executes.
#
# The gate is unavoidable: no valid, unused, in-scope token => no action.
# Nothing here reads the database or builds a command; it hands the token to
# the control plane, which re-verifies and then runs the fixed capability.
set -Eeuo pipefail
PATH='/data/data/com.termux/files/usr/bin:/usr/bin:/bin:/system/bin'
umask 077

ACB="${BROKER_BIN:-$HOME/projects/broker/bin/broker}"
TOKEN="${1:?usage: pod.sh <token> <target_id> <action> [pod_name]}"
TARGET="${2:?}"
ACTION="${3:?}"
POD="${4:-pod-$TARGET}"

exec "$ACB" run --token "$TOKEN" --target "$TARGET" --action "$ACTION" --pod "$POD"
