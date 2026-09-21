#!/usr/bin/env bash
# pod.sh — C: run one defined action against one target.
#
# Usage:
#     pod.sh <target> [<action>]
#
# <target> may be an alias from targets.conf or a literal IPv4 address.
# <action> defaults to $ACTION_DEFAULT. The action must exist as
#     $PODS_HOME/actions/<action>.sh  and be executable.
#
# CLUSTER LAW v1 safety gate (lib_safety_gate.sh, see CLUSTER_LAW.md): when
# <target> is an ALIAS (not a literal IP), it must be an ENROLLED, enabled
# pod in cluster.conf, and that pod's capability list must grant <action>,
# before the action is ever invoked. Enrollment (cluster.sh) is a separate,
# deliberate, operator-driven step — an alias merely present in
# targets.conf is not enough; being in targets.conf gives it an IP, not
# authorization. A literal-IP target has no pod identity to hold a grant,
# so it is never gated for an ordinary action -- except a root-requiring
# one (actions/<action>.root sentinel present), which is refused
# unconditionally on that path since there is no pod to hold a root-exec
# grant. This never widens what could already run; it only narrows it.
#
# Emits to $PODS_LOG and $PODS_RUNS:
#     stage=C event=start|finish|reject  status=ok|fail  ...
#
# Exit codes:
#     0   action succeeded
#     1   action reported fail (rc=action's own exit)
#     2   unknown target
#     3   unknown / non-executable action
#     5   denied by the safety gate (see $CLUSTER_LOG for the reason)
#
# This script is stateless. All rotation / trigger logic lives in rotator.sh.

set -eu

PODS_HOME="${PODS_HOME:-${HOME}/pods}"
# shellcheck disable=SC1091
. "${PODS_HOME}/pods.conf"
# shellcheck disable=SC1091
. "${PODS_HOME}/lib_safety_gate.sh"

if [ -e "$PODS_STOP" ]; then
    printf '%s stage=C event=skip reason=stop-sentinel status=refused\n' \
        "$(date -u +%FT%TZ)" >>"$PODS_LOG"
    exit 1
fi

[ $# -ge 1 ] || { echo "usage: $0 <target> [<action>]" >&2; exit 64; }
TARGET="$1"
ACTION="${2:-${ACTION_DEFAULT}}"

CHAIN_ID="${CHAIN_ID:-${CHAIN_PREFIX}-$(date +%s)}"
EXEC_ID="${EXEC_ID:-E$(printf '%08x' "$$" "$RANDOM")}"
HOP="${HOP:-0}"

ts() { date -u +%FT%TZ; }

# Resolve alias -> ip. A literal IPv4 address is used as-is.
if printf '%s' "$TARGET" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    IP="$TARGET"
    ALIAS=""
else
    IP=$(awk -F= -v k="$TARGET" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        $1 == k { gsub(/[[:space:]]/, "", $2); print $2; exit }
    ' "$PODS_TARGETS")
    if [ -z "$IP" ]; then
        ALIAS="$TARGET"
        printf '%s chain=%s exec=%s hop=%s target=%s stage=C event=reject reason=unknown-target status=fail\n' \
            "$(ts)" "$CHAIN_ID" "$EXEC_ID" "$HOP" "$TARGET" >>"$PODS_LOG"
        exit 2
    fi
    ALIAS="$TARGET"
fi

SCRIPT="${PODS_HOME}/actions/${ACTION}.sh"
if [ ! -x "$SCRIPT" ]; then
    printf '%s chain=%s exec=%s hop=%s target=%s stage=C event=reject reason=unknown-action action=%s status=fail\n' \
        "$(ts)" "$CHAIN_ID" "$EXEC_ID" "$HOP" "$TARGET" "$ACTION" >>"$PODS_LOG"
    exit 3
fi

# Safety gate (CLUSTER LAW v1). Alias-resolved targets must be an enrolled,
# capability-granted pod; literal-IP targets have no pod identity to check
# against, so they are ungated EXCEPT for a root-requiring action, which no
# unenrolled dispatch may ever run.
if [ -n "$ALIAS" ]; then
    if ! gate_check "$ALIAS" "$ACTION"; then
        printf '%s chain=%s exec=%s hop=%s target=%s stage=C event=reject reason=gate_denied gate_reason="%s" action=%s status=fail\n' \
            "$(ts)" "$CHAIN_ID" "$EXEC_ID" "$HOP" "$TARGET" "$GATE_REASON" "$ACTION" >>"$PODS_LOG"
        exit 5
    fi
elif requires_root "$ACTION"; then
    printf '%s chain=%s exec=%s hop=%s target=%s stage=C event=reject reason=gate_denied gate_reason="root-exec has no pod identity to hold a grant on a literal-IP target" action=%s status=fail\n' \
        "$(ts)" "$CHAIN_ID" "$EXEC_ID" "$HOP" "$TARGET" "$ACTION" >>"$PODS_LOG"
    exit 5
fi

START_S=$(date +%s)
printf '%s chain=%s exec=%s hop=%s target=%s ip=%s stage=C event=start action=%s status=ok\n' \
    "$(ts)" "$CHAIN_ID" "$EXEC_ID" "$HOP" "$TARGET" "$IP" "$ACTION" >>"$PODS_LOG"

set +e
"$SCRIPT" "$TARGET" "$IP"
RC=$?
set -e

END_S=$(date +%s)
DUR=$((END_S - START_S))

if [ "$RC" -eq 0 ]; then
    printf '%s chain=%s exec=%s hop=%s target=%s ip=%s stage=C event=finish action=%s status=ok duration_s=%d\n' \
        "$(ts)" "$CHAIN_ID" "$EXEC_ID" "$HOP" "$TARGET" "$IP" "$ACTION" "$DUR" >>"$PODS_LOG"
    printf '{"ts":"%s","chain":"%s","exec":"%s","hop":%s,"target":"%s","alias":"%s","ip":"%s","action":"%s","outcome":"ok","duration_s":%d}\n' \
        "$(ts)" "$CHAIN_ID" "$EXEC_ID" "$HOP" "$TARGET" "$ALIAS" "$IP" "$ACTION" "$DUR" >>"$PODS_RUNS"
    exit 0
else
    printf '%s chain=%s exec=%s hop=%s target=%s ip=%s stage=C event=finish action=%s status=fail rc=%d duration_s=%d\n' \
        "$(ts)" "$CHAIN_ID" "$EXEC_ID" "$HOP" "$TARGET" "$IP" "$ACTION" "$RC" "$DUR" >>"$PODS_LOG"
    printf '{"ts":"%s","chain":"%s","exec":"%s","hop":%s,"target":"%s","alias":"%s","ip":"%s","action":"%s","outcome":"fail","rc":%d,"duration_s":%d}\n' \
        "$(ts)" "$CHAIN_ID" "$EXEC_ID" "$HOP" "$TARGET" "$ALIAS" "$IP" "$ACTION" "$RC" "$DUR" >>"$PODS_RUNS"
    exit "$RC"
fi