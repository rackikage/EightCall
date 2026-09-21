#!/usr/bin/env bash
# lib_safety_gate.sh — CLUSTER LAW v1 enforcement (read-only helpers).
#
# Deny-by-default boundary between a dispatch request (alias + action) and
# actually invoking an actions/*.sh script. Sourced by pod.sh, and by
# cluster.sh (which adds the write-side operations this file deliberately
# does not have). See CLUSTER_LAW.md for the full law this encodes; the
# short version:
#
#   TARGET has one stable DEVICE_ID
#   POD belongs to exactly one TARGET
#   POD NAME is editable metadata          (device identity != pod name)
#   IP / PORT / RADIO may change freely    (pod name != IP address)
#   UNKNOWN TARGET never becomes a pod automatically
#   DISCOVERY never equals enrollment
#   ROOT requires explicit root-exec authorization
#
# This library only READS $CLUSTER_CONF. Mutating it is cluster.sh's job
# (enroll / disable / enable / rename) — never do it here, and never from
# pod.sh, watcher.sh, or rotator.sh. Enrollment is a deliberate, explicit,
# operator-driven act; nothing on the automatic A -> B -> C path may ever
# write a row into the cluster ledger.

: "${PODS_HOME:=${HOME}/pods}"
: "${CLUSTER_CONF:=${PODS_HOME}/cluster.conf}"
: "${CLUSTER_LOG:=${PODS_HOME}/cluster.log}"

_gate_ts() { date -u +%FT%TZ; }

# One line per pod, tab-separated: pod_name\tdevice_id\tstatus\tcapabilities
# Comments (#) and blank lines are ignored. Returns "device_id\tstatus\tcaps"
# for the first matching pod_name, or nothing if unenrolled.
_cluster_row() {
    local pod="$1"
    [ -f "$CLUSTER_CONF" ] || return 0
    awk -F'\t' -v p="$pod" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        $1 == p { print $2 "\t" $3 "\t" $4; exit }
    ' "$CLUSTER_CONF"
}

# First pod_name currently enrolled under this device_id, or empty. Used by
# cluster.sh to enforce "one target = one pod" (a device_id may not be
# enrolled under two different pod names at once).
_find_pod_by_device_id() {
    local device_id="$1"
    [ -f "$CLUSTER_CONF" ] || return 0
    awk -F'\t' -v d="$device_id" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        $2 == d { print $1; exit }
    ' "$CLUSTER_CONF"
}

device_id_of()    { _cluster_row "$1" | awk -F'\t' '{print $1}'; }
status_of()        { _cluster_row "$1" | awk -F'\t' '{print $2}'; }
capabilities_of()  { _cluster_row "$1" | awk -F'\t' '{print $3}'; }

# Enrolled AND enabled. No row at all (unknown target, or discovered-but-
# never-enrolled) and a disabled row both refuse here — "unknown target
# never becomes a pod automatically" holds regardless of which case it is.
is_enrolled() {
    local pod="$1" st
    st=$(status_of "$pod")
    [ "$st" = "enabled" ]
}

# Deny-by-default: an empty or missing capability list grants nothing. A
# capability must be named EXACTLY (comma-separated, no globs) in the pod's
# enrolled list.
capability_granted() {
    local pod="$1" action="$2" caps
    caps=$(capabilities_of "$pod")
    [ -n "$caps" ] || return 1
    case ",$caps," in
        *",$action,"*) return 0 ;;
        *) return 1 ;;
    esac
}

# An action requires root-exec authorization iff a same-named .root sentinel
# file exists next to it (empty file; presence is the signal). No shipped
# action currently sets this — it exists so a future privileged action
# (e.g. actions/admin-shell.sh) can opt in without any pod.sh changes.
requires_root() {
    local action="$1"
    [ -f "${PODS_HOME}/actions/${action}.root" ]
}

# root-exec is itself just a capability, granted (or not) like any other,
# in ADDITION to the action's own capability — never in place of it.
root_exec_granted() {
    capability_granted "$1" "root-exec"
}

# decision(allow|deny) pod action reason -> one terse audit line.
_gate_audit() {
    printf '%s pod=%s action=%s decision=%s reason=%s\n' \
        "$(_gate_ts)" "$2" "$3" "$1" "$4" >> "$CLUSTER_LOG"
}

# The single entry point pod.sh calls before dispatching an alias-resolved
# action. Returns 0 = allow, 1 = deny. Always sets $GATE_REASON (human-
# readable) and appends exactly one line to $CLUSTER_LOG, allow or deny.
gate_check() {
    local pod="$1" action="$2"
    GATE_REASON=""

    if ! is_enrolled "$pod"; then
        GATE_REASON="pod '$pod' is not enrolled (or is disabled) in cluster.conf"
        _gate_audit deny "$pod" "$action" "not_enrolled"
        return 1
    fi

    if ! capability_granted "$pod" "$action"; then
        GATE_REASON="capability '$action' is not granted to pod '$pod'"
        _gate_audit deny "$pod" "$action" "capability_not_granted"
        return 1
    fi

    if requires_root "$action" && ! root_exec_granted "$pod"; then
        GATE_REASON="action '$action' requires root-exec, which is not granted to pod '$pod'"
        _gate_audit deny "$pod" "$action" "root_exec_not_granted"
        return 1
    fi

    GATE_REASON="granted"
    _gate_audit allow "$pod" "$action" "ok"
    return 0
}
