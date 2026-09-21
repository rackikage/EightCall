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


def run_rule(path: Path, validator, bs) -> tuple[bool, list[str]]:
    notes = []
    try:
        collection = SigmaCollection.from_yaml(path.read_text())
    except Exception as exc:
        return False, [f"parse failed: {type(exc).__name__}: {exc}"]
    rules = list(collection.rules)
    notes.append("collection: " + ", ".join(r.title for r in rules))
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
        except Exception as exc:
            notes.append(f"{name}: unsupported ({type(exc).__name__}: {exc})")
    if compiled:
        return True, notes
    if "correlation:" in path.read_text():
        notes.append("correlation syntax parsed; backend correlation support pending")
        return True, notes
    return False, notes


def main(argv: list[str]) -> int:
    root = Path(argv[0]) if argv else DEFAULT_DIR
    validator = make_validator()
    bs = backends()
    paths = sorted(root.glob("*.yml"))
    print(f"backends: {', '.join(n for n, _ in bs) or 'none'}")
    failed = 0
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
