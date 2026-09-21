#!/usr/bin/env bash
# cluster.sh — the ONLY sanctioned way to mutate cluster.conf (CLUSTER LAW v1).
#
# Usage:
#     cluster.sh enroll  --pod NAME --device-id ID --caps a,b,c [--force]
#     cluster.sh disable --pod NAME
#     cluster.sh enable  --pod NAME
#     cluster.sh rename  --old NAME --new NAME2
#     cluster.sh validate
#     cluster.sh list
#
# Enrollment is a deliberate, explicit, operator-driven act — never automatic.
# Nothing on the A -> B -> C path (watcher.sh / rotator.sh / pod.sh) may call
# this script or write to cluster.conf; they only ever READ it, through
# lib_safety_gate.sh's gate_check(). See CLUSTER_LAW.md for the full spec.
#
# Invariants enforced here, not just documented:
#   * one target = one pod: a device_id may not be enrolled under two
#     different pod names at once.
#   * a pod name already enrolled under a DIFFERENT device_id refuses a
#     re-enroll (identity reassignment) unless --force is given explicitly.
#   * rename keeps device_id fixed and moves only the pod-name label; it
#     refuses if the new name is already a different device's pod.
#   * copying a device_id or a private key is not a thing this script can
#     do — there is no read path for either that ever leaves cluster.conf.

set -eu

PODS_HOME="${PODS_HOME:-${HOME}/pods}"
# shellcheck disable=SC1091
. "${PODS_HOME}/pods.conf"
# shellcheck disable=SC1091
. "${PODS_HOME}/lib_safety_gate.sh"

ts() { date -u +%FT%TZ; }

_ensure_conf() { [ -f "$CLUSTER_CONF" ] || : > "$CLUSTER_CONF"; }

_cluster_audit() {
    # op(enroll|disable|enable|rename) pod decision(allow|deny) detail
    printf '%s pod=%s op=%s decision=%s detail=%s\n' \
        "$(ts)" "$2" "$1" "$3" "$4" >> "$CLUSTER_LOG"
}

# Remove any existing row for $1, atomically (mktemp + mv, matching
# watcher.sh's own state.tsv rewrite pattern — no partial-write window).
_remove_row() {
    local pod="$1" tmp
    _ensure_conf
    tmp=$(mktemp "${CLUSTER_CONF}.XXXXXX")
    awk -F'\t' -v p="$pod" '
        /^[[:space:]]*#/ { print; next }
        /^[[:space:]]*$/ { print; next }
        $1 == p { next }
        { print }
    ' "$CLUSTER_CONF" > "$tmp"
    mv -f "$tmp" "$CLUSTER_CONF"
}

_append_row() {
    # pod device_id status caps
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$CLUSTER_CONF"
}

_parse_kv() {
    # Fills the named vars from --flag value pairs. bash 3.2-safe: no
    # associative arrays, just a manual case loop (matches pod.sh/rotator.sh
    # style elsewhere in this tree).
    POD=""; DEVICE_ID=""; CAPS=""; FORCE=0; OLD=""; NEW=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --pod)       POD="$2"; shift 2 ;;
            --device-id) DEVICE_ID="$2"; shift 2 ;;
            --caps)      CAPS="$2"; shift 2 ;;
            --old)       OLD="$2"; shift 2 ;;
            --new)       NEW="$2"; shift 2 ;;
            --force)     FORCE=1; shift ;;
            *) echo "unknown argument: $1" >&2; exit 64 ;;
        esac
    done
}

cmd_enroll() {
    _parse_kv "$@"
    [ -n "$POD" ] && [ -n "$DEVICE_ID" ] || {
        echo "usage: cluster.sh enroll --pod NAME --device-id ID [--caps a,b,c] [--force]" >&2
        exit 64
    }
    _ensure_conf

    # one target = one pod: this device_id must not already belong to a
    # DIFFERENT pod name.
    local existing_pod
    existing_pod=$(_find_pod_by_device_id "$DEVICE_ID")
    if [ -n "$existing_pod" ] && [ "$existing_pod" != "$POD" ]; then
        echo "refused: device_id '$DEVICE_ID' is already enrolled as pod '$existing_pod' (one target = one pod; use rename instead)" >&2
        _cluster_audit enroll "$POD" deny "device_id_conflict:$existing_pod"
        exit 1
    fi

    # this pod name must not already point at a DIFFERENT device_id, unless
    # the operator explicitly says --force (identity reassignment, logged).
    local existing_device
    existing_device=$(device_id_of "$POD")
    if [ -n "$existing_device" ] && [ "$existing_device" != "$DEVICE_ID" ] && [ "$FORCE" -ne 1 ]; then
        echo "refused: pod '$POD' is already enrolled with a different device_id ('$existing_device'). Use --force to reassign, or rename the existing pod first." >&2
        _cluster_audit enroll "$POD" deny "identity_reassign_without_force"
        exit 1
    fi

    _remove_row "$POD"
    _append_row "$POD" "$DEVICE_ID" "enabled" "$CAPS"
    _cluster_audit enroll "$POD" allow "device_id=$DEVICE_ID caps=$CAPS"
    echo "enrolled pod '$POD' -> device_id '$DEVICE_ID' (caps: ${CAPS:-none})"
}

_set_status() {
    local pod="$1" new_status="$2" device_id caps
    device_id=$(device_id_of "$pod")
    [ -n "$device_id" ] || {
        echo "refused: pod '$pod' is not enrolled" >&2
        _cluster_audit "$new_status" "$pod" deny "not_enrolled"
        exit 1
    }
    caps=$(capabilities_of "$pod")
    _remove_row "$pod"
    _append_row "$pod" "$device_id" "$new_status" "$caps"
    _cluster_audit "$new_status" "$pod" allow "device_id=$device_id"
}

cmd_disable() {
    _parse_kv "$@"
    [ -n "$POD" ] || { echo "usage: cluster.sh disable --pod NAME" >&2; exit 64; }
    _set_status "$POD" "disabled"
    echo "disabled pod '$POD'"
}

cmd_enable() {
    _parse_kv "$@"
    [ -n "$POD" ] || { echo "usage: cluster.sh enable --pod NAME" >&2; exit 64; }
    _set_status "$POD" "enabled"
    echo "enabled pod '$POD'"
}

cmd_rename() {
    _parse_kv "$@"
    [ -n "$OLD" ] && [ -n "$NEW" ] || {
        echo "usage: cluster.sh rename --old NAME --new NAME2" >&2
        exit 64
    }
    local device_id status caps
    device_id=$(device_id_of "$OLD")
    [ -n "$device_id" ] || {
        echo "refused: pod '$OLD' is not enrolled" >&2
        _cluster_audit rename "$OLD" deny "not_enrolled"
        exit 1
    }
    status=$(status_of "$OLD")
    caps=$(capabilities_of "$OLD")

    # the new name must not already be a DIFFERENT device's pod.
    local new_existing
    new_existing=$(device_id_of "$NEW")
    if [ -n "$new_existing" ] && [ "$new_existing" != "$device_id" ]; then
        echo "refused: pod name '$NEW' already maps to a different device_id ('$new_existing')" >&2
        _cluster_audit rename "$OLD" deny "target_name_conflict:$NEW"
        exit 1
    fi

    _remove_row "$OLD"
    _remove_row "$NEW"
    _append_row "$NEW" "$device_id" "$status" "$caps"
    _cluster_audit rename "$OLD" allow "new=$NEW device_id=$device_id"
    echo "renamed pod '$OLD' -> '$NEW' (device_id unchanged: $device_id)"
}

cmd_validate() {
    _ensure_conf
    # A single awk pass: flags (a) any row with an empty device_id, and
    # (b) any device_id enrolled under more than one DISTINCT pod name
    # (tracked as a pod-name set per device_id, so a literal duplicate row
    # for the SAME pod is not mistaken for a second pod). "one target = one
    # pod" is exactly condition (b).
    awk -F'\t' '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        {
            pod = $1; device_id = $2
            if (device_id == "") {
                print "issue: pod " pod " has no device_id"
                issues++
                next
            }
            # SUBSEP-keyed single-dimension array (portable to BWK/POSIX awk,
            # unlike gawk-only arr[i][j] nesting) dedupes a literal duplicate
            # row for the SAME pod so it is never miscounted as a second pod.
            key = device_id SUBSEP pod
            if (!(key in seen_pair)) {
                seen_pair[key] = 1
                names[device_id] = (device_id in names) ? names[device_id] " " pod : pod
                count[device_id]++
            }
        }
        END {
            for (d in count) {
                if (count[d] > 1) {
                    print "issue: device_id " d " is enrolled under more than one pod name (one target = one pod violated):" names[d]
                    issues++
                }
            }
            print (issues > 0) ? "cluster.conf: " issues " issue(s)" : "cluster.conf: OK"
            exit (issues > 0) ? 1 : 0
        }
    ' "$CLUSTER_CONF"
}

cmd_list() {
    _ensure_conf
    printf '%-16s %-24s %-10s %s\n' "POD" "DEVICE_ID" "STATUS" "CAPABILITIES"
    awk -F'\t' '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        { printf "%-16s %-24s %-10s %s\n", $1, $2, $3, $4 }
    ' "$CLUSTER_CONF"
}

case "${1:-}" in
    enroll)   shift; cmd_enroll "$@" ;;
    disable)  shift; cmd_disable "$@" ;;
    enable)   shift; cmd_enable "$@" ;;
    rename)   shift; cmd_rename "$@" ;;
    validate) cmd_validate ;;
    list)     cmd_list ;;
    *)
        echo "usage: $0 {enroll|disable|enable|rename|validate|list} [args...]" >&2
        exit 64
        ;;
esac
