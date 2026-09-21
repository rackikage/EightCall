#!/usr/bin/env bash
# install.sh — copy the pods tree to $PODS_HOME (default ~/pods).
#
# Usage:
#     ./install.sh                      # install to ~/pods
#     PODS_HOME=/srv/pods ./install.sh  # install elsewhere
#     ./install.sh --force              # overwrite an existing tree

set -eu

PODS_HOME="${PODS_HOME:-${HOME}/pods}"
HERE="$(cd "$(dirname "$0")" && pwd)"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

if [ -e "$PODS_HOME" ] && [ "$FORCE" -ne 1 ]; then
    echo "install: $PODS_HOME already exists. Use --force to overwrite." >&2
    exit 1
fi

mkdir -p "$PODS_HOME/actions"

# Copy scripts (executable) and config (readable).
install -m 0755 "$HERE/pod.sh"               "$PODS_HOME/pod.sh"
install -m 0755 "$HERE/watcher.sh"           "$PODS_HOME/watcher.sh"
install -m 0755 "$HERE/rotator.sh"           "$PODS_HOME/rotator.sh"
install -m 0755 "$HERE/killswitch.sh"              "$PODS_HOME/killswitch.sh"
install -m 0755 "$HERE/state-receiver.sh"      "$PODS_HOME/state-receiver.sh"
install -m 0755 "$HERE/state_receiver.py"       "$PODS_HOME/state_receiver.py"
install -m 0755 "$HERE/lib_eligibility.sh"   "$PODS_HOME/lib_eligibility.sh"
install -m 0755 "$HERE/lib_safety_gate.sh"   "$PODS_HOME/lib_safety_gate.sh"
install -m 0755 "$HERE/cluster.sh"           "$PODS_HOME/cluster.sh"
install -m 0644 "$HERE/pods.conf"            "$PODS_HOME/pods.conf"
install -m 0644 "$HERE/targets.conf"         "$PODS_HOME/targets.conf"
install -m 0644 "$HERE/CLUSTER_LAW.md"       "$PODS_HOME/CLUSTER_LAW.md"

# cluster.conf is enrollment STATE, not code — never overwrite an existing
# one, even with --force (that would silently un-enroll every pod). Only
# seed the template on a genuinely fresh install.
if [ -e "$PODS_HOME/cluster.conf" ]; then
    echo "install: keeping existing $PODS_HOME/cluster.conf (enrollment is never overwritten)"
else
    install -m 0644 "$HERE/cluster.conf" "$PODS_HOME/cluster.conf"
fi

# Actions
install -m 0755 "$HERE/actions/health.sh"     "$PODS_HOME/actions/health.sh"
install -m 0755 "$HERE/actions/probe.sh"      "$PODS_HOME/actions/probe.sh"
install -m 0755 "$HERE/actions/inventory.sh"  "$PODS_HOME/actions/inventory.sh"

# State directory tree.
mkdir -p "$PODS_HOME/state" "$PODS_HOME/pids" "$PODS_HOME/locks"

echo "installed to $PODS_HOME"
echo
echo "next:"
echo "  1. edit $PODS_HOME/targets.conf to list your targets (alias=ip)"
echo "  2. enroll each pod (CLUSTER LAW v1 — see CLUSTER_LAW.md; a target is"
echo "     never dispatched to automatically until it is enrolled):"
echo "       $PODS_HOME/cluster.sh enroll --pod <alias> --device-id <id> --caps health,probe,inventory"
echo "       $PODS_HOME/cluster.sh validate"
echo "  3. start the daemons:"
echo "       $PODS_HOME/watcher.sh start"
echo "       $PODS_HOME/rotator.sh start"
echo "  4. follow the log:"
echo "       tail -F $PODS_HOME/pods.log | grep --line-buffered 'chain='"
echo "  5. stop them:"
echo "       $PODS_HOME/killswitch.sh"