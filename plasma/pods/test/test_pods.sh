#!/usr/bin/env bash
# test_pods.sh — bash-portable smoke tests for the pods/ tree.
#
# Runs under bash 3.2+ (the version macOS ships). Self-contained: builds a
# throwaway $PODS_HOME under $TMPDIR, never touches the user's real ~/pods.
#
# Usage:
#     ./test/test_pods.sh           # run all
#     ./test/test_pods.sh -v        # verbose: print each pass/fail line

set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
VERBOSE=0
[ "${1:-}" = "-v" ] && VERBOSE=1

PASS=0
FAIL=0

ok()  { printf '  PASS %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL %s\n' "$1"; FAIL=$((FAIL + 1)); }
note() { [ "$VERBOSE" = 1 ] && printf '       %s\n' "$1" || true; }

# --- setup ---------------------------------------------------------------

TMP="${TMPDIR:-/tmp}/pods-test.$$"
mkdir -p "$TMP/pods/actions" "$TMP/pods/state" "$TMP/pods/pids" "$TMP/pods/locks"
export PODS_HOME="$TMP/pods"
export PODS_TARGETS="$TMP/pods/targets.conf"

# Mirror pods.conf + actions/ + lib_eligibility.sh + lib_safety_gate.sh +
# pod.sh into the throwaway $PODS_HOME so the scripts can source / invoke
# them the way they will in production.
cp "$HERE/pods.conf" "$PODS_HOME/pods.conf"
cp "$HERE/lib_eligibility.sh" "$PODS_HOME/lib_eligibility.sh"
cp "$HERE/lib_safety_gate.sh" "$PODS_HOME/lib_safety_gate.sh"
install -m 0755 "$HERE/pod.sh"               "$PODS_HOME/pod.sh"
install -m 0755 "$HERE/actions/health.sh"    "$PODS_HOME/actions/health.sh"
install -m 0755 "$HERE/actions/probe.sh"     "$PODS_HOME/actions/probe.sh"
install -m 0755 "$HERE/actions/inventory.sh" "$PODS_HOME/actions/inventory.sh"

cat > "$PODS_TARGETS" <<EOF
# test fixtures
loopback=127.0.0.1
blackhole=192.0.2.1
EOF

# CLUSTER LAW v1: pod.sh's gate refuses to dispatch to an alias that is not
# an ENROLLED, enabled pod in cluster.conf -- being merely listed in
# targets.conf (which only supplies an IP) is not enough. Enroll the fixture
# the pre-existing pod.sh-contract tests below dispatch to; "blackhole" is
# deliberately left UNENROLLED so the new gate tests can prove the point.
"$HERE/cluster.sh" enroll --pod loopback --device-id test-device-loopback \
    --caps health,probe,inventory >/dev/null

# --- syntax check ---------------------------------------------------------

echo "== bash -n on every shipped script =="
for s in pod.sh watcher.sh rotator.sh killswitch.sh install.sh \
         state-receiver.sh state_receiver.py \
         lib_eligibility.sh lib_safety_gate.sh cluster.sh \
         actions/health.sh actions/probe.sh actions/inventory.sh; do
    if [[ "$s" == *.py ]]; then
        # Python scripts: check via ast (no `bash -n`).
        if "$PODS_HOME/../../bin/python3" -c "import ast,sys; ast.parse(open('$HERE/$s').read())" 2>/dev/null \
           || /usr/bin/env python3 -c "import ast,sys; ast.parse(open('$HERE/$s').read())" 2>/dev/null; then
            ok "syntax: $s"
        else
            bad "syntax: $s (python ast)"
        fi
    else
        if bash -n "$HERE/$s" 2>/dev/null; then
            ok "syntax: $s"
        else
            bad "syntax: $s"
            bash -n "$HERE/$s"
        fi
    fi
done

# --- pod.sh contract ------------------------------------------------------

echo "== pod.sh contract =="

# 1. health action against loopback should succeed (localhost responds to ping).
if "$HERE/pod.sh" loopback health >/dev/null 2>&1; then
    ok "pod.sh loopback health -> exit 0"
else
    bad "pod.sh loopback health -> expected success"
fi
note "$(tail -1 "$TMP/pods/pods.log" 2>/dev/null || echo '(no log)')"

# 2. unknown alias -> reject, exit 2, log "unknown-target".
if "$HERE/pod.sh" no-such-alias health >/dev/null 2>&1; then rc=0; else rc=$?; fi
[ "$rc" = "2" ] && ok "pod.sh unknown alias -> exit 2" || bad "pod.sh unknown alias -> exit was $rc"
grep -q 'reason=unknown-target' "$TMP/pods/pods.log" && ok "pod.sh unknown alias -> logged" || bad "pod.sh unknown alias -> not logged"

# 3. unknown action -> exit 3, log "unknown-action".
if "$HERE/pod.sh" loopback no-such-action >/dev/null 2>&1; then rc=0; else rc=$?; fi
[ "$rc" = "3" ] && ok "pod.sh unknown action -> exit 3" || bad "pod.sh unknown action -> exit was $rc"
grep -q 'reason=unknown-action' "$TMP/pods/pods.log" && ok "pod.sh unknown action -> logged" || bad "pod.sh unknown action -> not logged"

# 4. literal IP works without a targets.conf entry.
if "$HERE/pod.sh" 127.0.0.1 health >/dev/null 2>&1; then
    ok "pod.sh literal ip -> exit 0"
else
    bad "pod.sh literal ip -> expected success"
fi

# 5. runs.jsonl gets one record per pod invocation.
runs_count=$(wc -l < "$TMP/pods/runs.jsonl" | tr -d ' ')
[ "$runs_count" -ge 2 ] && ok "pod.sh writes runs.jsonl (>=2 records)" || bad "pod.sh runs.jsonl count=$runs_count"
note "runs.jsonl: $(head -1 "$TMP/pods/runs.jsonl")"

# 6. log format is space-separated key=value.
log_line=$(grep 'stage=C event=finish' "$TMP/pods/pods.log" | head -1)
echo "$log_line" | grep -q 'chain=' && \
echo "$log_line" | grep -q 'exec=' && \
echo "$log_line" | grep -q 'hop=' && \
echo "$log_line" | grep -q 'target=' && \
echo "$log_line" | grep -q 'stage=C' && \
echo "$log_line" | grep -q 'event=finish' && \
echo "$log_line" | grep -q 'action=' && \
echo "$log_line" | grep -q 'status=' && \
    ok "log line key=value shape" || bad "log line shape: $log_line"

# --- CLUSTER LAW v1 safety gate -------------------------------------------

echo "== safety gate (cluster.conf / lib_safety_gate.sh / cluster.sh) =="

# A synthetic, deterministic action (always exit 0) for the assertions
# below -- unlike probe.sh/health.sh, its outcome never depends on real
# network/port state, so a gate-allow can be told apart from an action's
# own success/failure with certainty.
cat > "$PODS_HOME/actions/okaction.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$PODS_HOME/actions/okaction.sh"

# 7. an alias present in targets.conf but NEVER enrolled is denied: exit 5,
#    reason=gate_denied in pods.log, not_enrolled in cluster.log. Being
#    reachable (has an IP) is not the same as being authorized.
if "$HERE/pod.sh" blackhole health >/dev/null 2>&1; then rc=0; else rc=$?; fi
[ "$rc" = "5" ] && ok "gate: unenrolled alias -> exit 5" || bad "gate: unenrolled alias -> exit was $rc"
grep -q 'reason=gate_denied' "$TMP/pods/pods.log" && ok "gate: unenrolled alias -> logged in pods.log" || bad "gate: unenrolled alias -> not logged"
grep -q 'not_enrolled' "$TMP/pods/cluster.log" && ok "gate: unenrolled -> cluster.log records not_enrolled" || bad "gate: cluster.log missing not_enrolled"

# 8. an enrolled pod dispatching an action NOT in its capability list is
#    denied (deny-by-default): grant only "okaction", ask for "health".
"$HERE/cluster.sh" enroll --pod probeonly --device-id test-device-probeonly --caps okaction >/dev/null
cat >> "$PODS_TARGETS" <<EOF
probeonly=127.0.0.1
EOF
if "$HERE/pod.sh" probeonly health >/dev/null 2>&1; then rc=0; else rc=$?; fi
[ "$rc" = "5" ] && ok "gate: capability not granted -> exit 5" || bad "gate: capability not granted -> exit was $rc"
grep -q 'capability_not_granted' "$TMP/pods/cluster.log" && ok "gate: cluster.log records capability_not_granted" || bad "gate: cluster.log missing capability_not_granted"

# 9. the SAME pod dispatching its GRANTED action succeeds.
if "$HERE/pod.sh" probeonly okaction >/dev/null 2>&1; then ok "gate: granted capability -> exit 0"; else bad "gate: granted capability -> expected success"; fi

# 10. literal-IP dispatch stays completely ungated for a non-root action
#     (pre-existing test #4's guarantee, re-asserted here under the gate's
#     name so a regression that starts gating literal IPs is caught here).
if "$HERE/pod.sh" 127.0.0.1 okaction >/dev/null 2>&1; then ok "gate: literal IP stays ungated for a non-root action"; else bad "gate: literal IP was unexpectedly gated"; fi

# 11. cluster.sh: one target = one pod -- a device_id already enrolled under
#     a different pod name is refused.
if "$HERE/cluster.sh" enroll --pod probeonly-2 --device-id test-device-probeonly --caps okaction >/dev/null 2>&1; then
    bad "cluster.sh: duplicate device_id under a new pod name should be refused"
else
    ok "cluster.sh: duplicate device_id under a new pod name refused"
fi

# 12. cluster.sh: reassigning an EXISTING pod name to a DIFFERENT device_id
#     is refused without --force, and applies with --force. Re-enrolling
#     the SAME pod+device_id (e.g. to update capabilities) needs no --force.
if "$HERE/cluster.sh" enroll --pod probeonly --device-id some-other-device --caps okaction >/dev/null 2>&1; then
    bad "cluster.sh: identity reassignment without --force should be refused"
else
    ok "cluster.sh: identity reassignment without --force refused"
fi
"$HERE/cluster.sh" enroll --pod probeonly --device-id some-other-device --caps okaction --force >/dev/null
[ "$(awk -F'\t' '$1=="probeonly"{print $2}' "$TMP/pods/cluster.conf")" = "some-other-device" ] \
    && ok "cluster.sh: --force reassignment applied" || bad "cluster.sh: --force reassignment did not apply"

# 13. cluster.sh rename: pod name moves, device_id stays fixed. The OLD name
#     becomes unenrolled (gate denies it); the NEW name is enrolled with the
#     SAME capabilities and passes the gate for its granted action.
"$HERE/cluster.sh" rename --old probeonly --new probeonly-renamed >/dev/null
if "$HERE/pod.sh" probeonly okaction >/dev/null 2>&1; then bad "rename: old name should no longer be enrolled"; else ok "rename: old name no longer enrolled"; fi
cat >> "$PODS_TARGETS" <<EOF
probeonly-renamed=127.0.0.1
EOF
if "$HERE/pod.sh" probeonly-renamed okaction >/dev/null 2>&1; then ok "rename: new name enrolled, capability preserved"; else bad "rename: new name should be enrolled"; fi

# 14. cluster.sh rename refuses to move a name onto an EXISTING different device.
if "$HERE/cluster.sh" rename --old probeonly-renamed --new loopback >/dev/null 2>&1; then
    bad "rename: collision with a different device's pod name should be refused"
else
    ok "rename: collision with a different device's pod name refused"
fi

# 15. cluster.sh disable / enable round-trip: a disabled pod is denied
#     exactly like an unenrolled one (not_enrolled is the same reason --
#     the gate makes no distinction between "never enrolled" and
#     "enrolled but disabled").
"$HERE/cluster.sh" disable --pod probeonly-renamed >/dev/null
if "$HERE/pod.sh" probeonly-renamed okaction >/dev/null 2>&1; then bad "disable: pod should be denied while disabled"; else ok "disable: pod denied while disabled"; fi
"$HERE/cluster.sh" enable --pod probeonly-renamed >/dev/null
if "$HERE/pod.sh" probeonly-renamed okaction >/dev/null 2>&1; then ok "enable: pod allowed again after re-enable"; else bad "enable: pod should be allowed again"; fi

# 16. cluster.sh validate: the clean file passes; a hand-corrupted one (two
#     pod names sharing one device_id) is caught, then cleaned back out.
if "$HERE/cluster.sh" validate >/dev/null 2>&1; then ok "cluster.sh validate: clean file passes"; else bad "cluster.sh validate: clean file should pass"; fi
printf 'evil-a\tshared-device\tenabled\thealth\n' >> "$PODS_HOME/cluster.conf"
printf 'evil-b\tshared-device\tenabled\thealth\n' >> "$PODS_HOME/cluster.conf"
if "$HERE/cluster.sh" validate >/dev/null 2>&1; then bad "cluster.sh validate: should have caught the duplicate device_id"; else ok "cluster.sh validate: duplicate device_id caught"; fi
awk -F'\t' '$1 != "evil-a" && $1 != "evil-b"' "$PODS_HOME/cluster.conf" > "$PODS_HOME/cluster.conf.clean"
mv "$PODS_HOME/cluster.conf.clean" "$PODS_HOME/cluster.conf"

# 17. root-exec: an action marked <action>.root requires the literal
#     "root-exec" capability IN ADDITION to its own -- granting the action
#     alone is not enough, and re-enrolling the SAME device to add a
#     capability needs no --force. A literal-IP target can never hold the
#     grant (there is no pod identity to hold it against), so it is refused
#     unconditionally regardless of cluster.conf.
cat > "$PODS_HOME/actions/priv.sh" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$PODS_HOME/actions/priv.sh"
touch "$PODS_HOME/actions/priv.root"
"$HERE/cluster.sh" enroll --pod loopback --device-id test-device-loopback \
    --caps health,probe,inventory,priv >/dev/null
if "$HERE/pod.sh" loopback priv >/dev/null 2>&1; then bad "root-exec: action-only grant should not be enough"; else ok "root-exec: action-only grant refused"; fi
"$HERE/cluster.sh" enroll --pod loopback --device-id test-device-loopback \
    --caps health,probe,inventory,priv,root-exec >/dev/null
if "$HERE/pod.sh" loopback priv >/dev/null 2>&1; then ok "root-exec: action + root-exec grant succeeds"; else bad "root-exec: should succeed once both are granted"; fi
if "$HERE/pod.sh" 127.0.0.1 priv >/dev/null 2>&1; then bad "root-exec: literal IP must never run a root-requiring action"; else ok "root-exec: literal IP refused (no pod identity to hold the grant)"; fi

# --- A and B unit-style checks -------------------------------------------

echo "== A & B unit checks =="

# Set up a state.tsv where loopback is UP and blackhole is DOWN; both
# were never recorded before.
cat > "$TMP/pods/state/state.tsv" <<EOF
loopback	127.0.0.1	UP	$(date +%s)
blackhole	192.0.2.1	DOWN	$(date +%s)
EOF

# 7. rotator.sh's eligibility: loopback should be eligible, blackhole should not.
#    (we source the helper functions rather than running the daemon).
( export PODS_HOME="$TMP/pods"
  if . "$HERE/lib_eligibility.sh" && eligible loopback; then ok "eligible: UP target"; else bad "eligible: UP target should pass"; fi )
( export PODS_HOME="$TMP/pods"
  if . "$HERE/lib_eligibility.sh" && eligible blackhole; then bad "eligible: DOWN target should fail"; else ok "eligible: DOWN target refused"; fi )

# 8. cooldown: simulate a recent dispatch and check it is in cooldown.
printf 'loopback\t%s\n' "$(date +%s)" > "$TMP/pods/state/last_dispatch.tsv"
( export PODS_HOME="$TMP/pods"
  if . "$HERE/lib_eligibility.sh" && eligible loopback; then bad "cooldown: recent dispatch should be ineligible"; else ok "cooldown: recent dispatch refused"; fi )

echo "== killswitch.sh end-to-end =="

# Start watcher + rotator in background, fire, confirm they stop.
"$HERE/watcher.sh" start
"$HERE/rotator.sh" start

# Both PID files should exist briefly after start.
sleep 0.4
wpid=""; rpid=""
[ -f "$TMP/pods/pids/watcher.pid" ] && wpid=$(cat "$TMP/pods/pids/watcher.pid")
[ -f "$TMP/pods/pids/rotator.pid" ] && rpid=$(cat "$TMP/pods/pids/rotator.pid")
[ -n "$wpid" ] && ok "watcher.sh started (pid=$wpid)" || bad "watcher.sh did not start"
[ -n "$rpid" ] && ok "rotator.sh started (pid=$rpid)" || bad "rotator.sh did not start"

"$HERE/killswitch.sh"

# After fire, both PID files should be gone (start-state re-init aside, the
# daemon-control commands remove them as part of stop).
dead_w=0; dead_r=0
[ -n "$wpid" ] && kill -0 "$wpid" 2>/dev/null || dead_w=1
[ -n "$rpid" ] && kill -0 "$rpid" 2>/dev/null || dead_r=1
[ "$dead_w" = "1" ] && ok "killswitch.sh stopped watcher" || bad "killswitch.sh: watcher pid=$wpid still alive"
[ "$dead_r" = "1" ] && ok "killswitch.sh stopped rotator" || bad "killswitch.sh: rotator pid=$rpid still alive"

# --- teardown -------------------------------------------------------------

rm -rf "$TMP"
echo
echo "== RESULT: $PASS pass, $FAIL fail =="
exit $((FAIL > 0 ? 1 : 0))