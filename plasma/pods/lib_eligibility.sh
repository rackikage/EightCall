#!/usr/bin/env bash
# lib_eligibility.sh — helpers shared by rotator.sh and the tests.
#
# Sourced by rotator.sh at startup (NOT run on its own). Provides:
#   in_cooldown <alias>           -> exit 0 if last dispatch is within
#                                    $COOLDOWN_SECONDS; else 1
#   eligible <alias>              -> exit 0 if alias is UP per state.tsv
#                                    AND not in cooldown; else 1
#   pick_eligible                  -> stdout: first eligible alias in
#                                    targets.conf order; exit 1 if none

# When sourced outside the daemon (e.g. by tests), the caller has not yet
# sourced pods.conf. Provide the minimum defaults so the helpers work
# without `set -eu` blowing up.
: "${PODS_HOME:=${HOME}/pods}"
: "${PODS_STATE:=${PODS_HOME}/state}"
: "${PODS_TARGETS:=${PODS_HOME}/targets.conf}"
: "${COOLDOWN_SECONDS:=120}"

# Is the alias in cooldown? Returns 0 (yes) if last dispatch < COOLDOWN_SECONDS ago.
in_cooldown() {
    local alias at last
    alias="$1"
    at=$(date +%s)
    last=$(awk -F'\t' -v a="$alias" '$1==a {print $2; exit}' "$PODS_STATE/last_dispatch.tsv" 2>/dev/null || echo "")
    [ -n "$last" ] || return 1
    [ $((at - last)) -lt "${COOLDOWN_SECONDS:-120}" ]
}

# Eligibility: alias's state is UP and not in cooldown.
eligible() {
    local alias status
    alias="$1"
    status=$(awk -F'\t' -v a="$alias" '$1==a {print $3; exit}' "$PODS_STATE/state.tsv" 2>/dev/null || echo "UNKNOWN")
    [ "$status" = "UP" ] || return 1
    in_cooldown "$alias" && return 1
    return 0
}

# Pick the next eligible alias. Prefer one in the order they appear in
# targets.conf (stable, predictable).
pick_eligible() {
    while IFS='=' read -r alias _ip; do
        case "$alias" in
            ''|\#*) continue ;;
        esac
        if eligible "$alias"; then
            printf '%s\n' "$alias"
            return 0
        fi
    done < "$PODS_TARGETS"
    return 1
}