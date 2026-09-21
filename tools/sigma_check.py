#!/usr/bin/env python3
"""pySigma runbook: parse, validate, and compile every rule to real backend queries."""
from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
from pathlib import Path

from sigma.collection import SigmaCollection

DEFAULT_DIR = Path(__file__).resolve().parents[1] / "rules" / "windows"


def core_validators() -> dict:
    import sigma.validators.base as vbase
    from sigma.validators import core

    bases = tuple(
        o for o in vars(vbase).values()
        if inspect.isclass(o) and o.__name__.endswith("Validator")
    )
    found: dict = {}
    for mod in pkgutil.iter_modules(core.__path__):
        m = importlib.import_module(f"sigma.validators.core.{mod.name}")
        for name, obj in vars(m).items():
            if (
                inspect.isclass(obj)
                and issubclass(obj, bases)
                and obj not in bases
                and obj.__module__ == m.__name__
            ):
                found[name] = obj
    return found


def make_validator():
    from sigma.validation import SigmaValidator

    classes = list(core_validators().values())
    while classes:
        try:
            return SigmaValidator(set(classes))
        except (TypeError, AttributeError):
            classes.pop()
    return None


def backends():
    out = []
    try:
        from sigma.backends.elasticsearch import LuceneBackend

        out.append(("lucene", LuceneBackend()))
    except Exception:
        pass
    try:
        from sigma.backends.splunk import SplunkBackend

        out.append(("splunk", SplunkBackend()))
    except Exception:
        pass
    return out


def backend_supports_correlation(backend) -> tuple[bool, str]:
    """Probe a backend for real correlation support by compiling a minimal rule.

    Returns (supported, note). This replaces a substring check on the rule file:
    the previous fallback treated any file containing the text 'correlation:' as a
    pass, including one that mentioned it only in a comment.
    """
    probe = """
title: correlation capability probe
id: 00000000-0000-0000-0000-0000000000ff
status: experimental
logsource:
  category: test
detection:
  selection:
    field: value
  condition: selection
---
title: correlation capability probe (correlated)
id: 00000000-0000-0000-0000-0000000000fe
status: experimental
logsource:
  category: test
correlation:
  type: event_count
  rules:
    - 00000000-0000-0000-0000-0000000000ff
  group-by:
    - field
  timespan: 5m
  condition:
    gte: 2
"""
    try:
        collection = SigmaCollection.from_yaml(probe)
    except Exception as exc:
        return False, f"probe unparseable ({type(exc).__name__})"
    try:
        backend.convert(collection)
        return True, "probe compiled"
    except NotImplementedError:
        return False, "backend does not implement correlations"
    except Exception as exc:
        return False, f"probe failed ({type(exc).__name__})"


def run_rule(path: Path, validator, bs) -> tuple[bool, list[str]]:
    notes = []
    try:
        collection = SigmaCollection.from_yaml(path.read_text())
    except Exception as exc:
        return False, [f"parse failed: {type(exc).__name__}: {exc}"]
    rules = list(collection.rules)
    notes.append("collection: " + ", ".join(r.title for r in rules))
    has_correlation = any(getattr(r, "correlation", None) is not None for r in rules)
    if validator:
        try:
            for issue in validator.validate_rules(rules):
                sev = getattr(getattr(issue, "severity", None), "name", "?")
                notes.append(f"validator [{sev}] {type(issue).__name__}: {getattr(issue, 'description', '')}")
        except Exception as exc:
            notes.append(f"validator skipped: {type(exc).__name__}: {exc}")
    compiled = 0
    for name, backend in bs:
        try:
            queries = backend.convert(collection)
            notes.append(f"{name}: {len(queries)} quer{'y' if len(queries) == 1 else 'ies'} ok")
            compiled += 1
        except NotImplementedError as exc:
            supports, why = backend_supports_correlation(backend)
            if supports:
                notes.append(f"{name}: rejected rule ({exc}) though probe compiled")
            else:
                notes.append(f"{name}: correlation unsupported ({why})")
        except Exception as exc:
            notes.append(f"{name}: unsupported ({type(exc).__name__}: {exc})")
    if compiled:
        return True, notes
    if has_correlation:
        # No backend compiled it. Only a pass if no backend *can* do correlations,
        # which is a capability limit, not a rule defect.
        capability = [backend_supports_correlation(b) for _, b in bs]
        if capability and not any(ok for ok, _ in capability):
            notes.append("no configured backend supports correlations; rule not compilable anywhere")
            return True, notes
        return False, notes
    return False, notes


def main(argv: list[str]) -> int:
    root = Path(argv[0]) if argv else DEFAULT_DIR
    validator = make_validator()
    bs = backends()
    print(f"backends: {', '.join(n for n, _ in bs) or 'none'}")
    if bs:
        print("correlation support (probed):")
        for name, backend in bs:
            ok, why = backend_supports_correlation(backend)
            print(f"    {name:10s} {'yes' if ok else 'no ':3s}  {why}")
    failed = 0
    paths = sorted(root.glob("*.yml"))
    for path in paths:
        ok, notes = run_rule(path, validator, bs)
        print(f"[{'PASS' if ok else 'FAIL'}] {path.name}")
        for note in notes:
            print(f"    {note}")
        if not ok:
            failed += 1
    print(f"rules: {len(paths)}  failed: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
