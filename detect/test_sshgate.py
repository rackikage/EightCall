#!/usr/bin/env python3
"""sshgate tests: the SSH-acceptance gate is deny-by-default and constraint-checked."""
from __future__ import annotations

from datetime import datetime, timezone

import nodebox_sshgate as sg

POLICY = "sshgate_policy.yml"
OPERATOR_FP = "SHA256:BhB8DBI/Wc2by/jq4Kh7DDBCr3mmfpfUQBWe0o1W2us"


def pol():
    return sg.load_policy(POLICY)


def test_fingerprint_matches_policy_key():
    p = pol()
    key = p["principals"][0]["key"]
    assert sg.fingerprint_of(key) == OPERATOR_FP == p["principals"][0]["fingerprint"]


def test_forward_to_granted_destination_allowed():
    d = sg.authorize(pol(), OPERATOR_FP, "forward", "fleet-node",
                     forward="127.0.0.1:8088", source_ip="192.168.8.50")
    assert d.allow and d.principal == "operator"


def test_forward_to_ungranted_destination_denied():
    d = sg.authorize(pol(), OPERATOR_FP, "forward", "fleet-node",
                     forward="127.0.0.1:9999", source_ip="192.168.8.50")
    assert not d.allow and "not granted" in d.reason


def test_unknown_key_denied():
    d = sg.authorize(pol(), "SHA256:AAAAunknown", "forward", "fleet-node",
                     forward="127.0.0.1:8088", source_ip="192.168.8.50")
    assert not d.allow and "unknown principal" in d.reason


def test_out_of_source_cidr_denied():
    d = sg.authorize(pol(), OPERATOR_FP, "forward", "fleet-node",
                     forward="127.0.0.1:8088", source_ip="10.9.9.9")
    assert not d.allow and "source" in d.reason


def test_expired_grant_denied():
    later = datetime(2027, 6, 1, tzinfo=timezone.utc)
    d = sg.authorize(pol(), OPERATOR_FP, "forward", "fleet-node",
                     forward="127.0.0.1:8088", source_ip="192.168.8.50", now=later)
    assert not d.allow and "validity window" in d.reason


def test_unknown_action_denied():
    d = sg.authorize(pol(), OPERATOR_FP, "reboot", "fleet-node", source_ip="192.168.8.50")
    assert not d.allow


def test_authorized_keys_are_restrictive():
    lines = sg.render_authorized_keys(pol(), "operator")
    assert len(lines) >= 3
    for ln in lines:
        assert ln.startswith("restrict")
    fwd = [ln for ln in lines if "permitopen" in ln]
    assert fwd and all('from="192.168.8.0/24"' in ln for ln in fwd)
    task = [ln for ln in lines if "command=" in ln]
    assert task and "collect-health" in task[0]


def test_sshd_match_enforces_permitopen_and_forcecommand():
    cfg = sg.render_sshd_match(pol())
    assert "Match User gw-fwd" in cfg and "Match User gw-task" in cfg and "Match User gw-shell" in cfg
    assert "PermitOpen" in cfg and "127.0.0.1:30090" in cfg
    assert "ForceCommand" in cfg and "collect-health" in cfg
    assert "PasswordAuthentication no" in cfg
    assert "CONFLICT" not in cfg


def test_policy_validates_clean():
    assert sg.validate_policy(pol()) == []


def test_policy_rejects_non_sshd_target():
    """The auth gate must not authorize SSH to a host that does not run sshd."""
    p = pol()
    p["principals"][0]["grants"].append({
        "action": "shell", "sshd_user": "gw-shell", "targets": ["b628"],
        "source_cidrs": ["192.168.8.0/24"], "not_after": "2026-12-31T23:59:59Z"})
    issues = sg.validate_policy(p)
    assert any("does not run sshd" in i and "b628" in i for i in issues)


def test_policy_validator_catches_mixed_user():
    p = pol()
    p["principals"][0]["grants"][2]["sshd_user"] = "gw-fwd"  # task shares forward user
    issues = sg.validate_policy(p)
    assert any("mixes actions" in i for i in issues)


# --- no random shells --------------------------------------------------------

def test_shell_requires_explicit_port():
    d = sg.authorize(pol(), OPERATOR_FP, "shell", "fleet-node", source_ip="192.168.8.50")
    assert not d.allow and "explicit --port" in d.reason


def test_shell_on_allowlisted_port_allowed():
    d = sg.authorize(pol(), OPERATOR_FP, "shell", "fleet-node",
                     port=2222, source_ip="192.168.8.50")
    assert d.allow


def test_shell_denies_non_allowlisted_port():
    d = sg.authorize(pol(), OPERATOR_FP, "shell", "fleet-node",
                     port=4444, source_ip="192.168.8.50")
    assert not d.allow and "not in sshd_ports" in d.reason


def test_root_shell_denied_without_grant():
    d = sg.authorize(pol(), OPERATOR_FP, "shell", "fleet-node",
                     port=2222, as_root=True, source_ip="192.168.8.50")
    assert not d.allow and "root shell not granted" in d.reason


def test_task_bound_to_declared_port():
    ok = sg.authorize(pol(), OPERATOR_FP, "task", "fleet-node",
                      port=2222, source_ip="192.168.8.50")
    assert ok.allow
    bad = sg.authorize(pol(), OPERATOR_FP, "task", "fleet-node",
                       port=22, source_ip="192.168.8.50")
    assert not bad.allow
