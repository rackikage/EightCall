#!/usr/bin/env python3
"""pySigma runbook for the shell-abuse rule.

The project's own `validate_rules.py` is a minimal hand-rolled evaluator; the
RUNBOOK's known-limitations note says to re-check rules against a real Sigma
engine before shipping. This does exactly that for `rules/ios_shell_abuse.yml`:

  1. PARSE   — load the rule with pySigma (validates Sigma structure,
               modifiers, and the condition grammar).
  2. VALIDATE— run pySigma's core validators and report issues.
  3. COMPILE — convert to real backend queries (Elasticsearch Lucene + DSL),
               proving the rule is queryable, not just syntactically valid.

Run:
    ./venv69/bin/python3 pysigma_shells.py [path/to/rule.yml]
"""
from __future__ import annotations

import sys
from pathlib import Path

from sigma.collection import SigmaCollection

RULE = "rules/ios_shell_abuse.yml"


def parse(path: Path) -> SigmaCollection:
    collection = SigmaCollection.from_yaml(path.read_text())
    for rule in collection.rules:
        print(f"  title:     {rule.title}")
        print(f"  id:        {rule.id}")
        print(f"  level:     {getattr(rule.level, 'name', rule.level)}")
        print(f"  status:    {getattr(rule.status, 'name', rule.status)}")
        ls = rule.logsource
        print(f"  logsource: product={ls.product} service={ls.service}")
        print(f"  selections: {sorted(rule.detection.detections)}")
        print(f"  condition:  {' '.join(rule.detection.condition)}")
    return collection


def _core_validator_classes() -> dict:
    """pySigma 1.5 scatters core validators across sigma.validators.core.*
    submodules with no single registry; collect the concrete ones."""
    import importlib
    import inspect
    import pkgutil

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


def validate(collection: SigmaCollection) -> int:
    from sigma.validation import SigmaValidator

    # SigmaValidator instantiates the classes itself (passing per-validator
    # config), so hand it the classes. Drop any that demand mandatory config.
    classes = list(_core_validator_classes().values())
    validator = None
    while classes:
        try:
            validator = SigmaValidator(set(classes))
            break
        except (TypeError, AttributeError):
            classes.pop()  # a validator needed config; retry without it
    if validator is None:
        print("  (no zero-config validators available)")
        return 0
    issues = validator.validate_rules(list(collection.rules))
    print(f"  loaded {len(classes)} core validators")
    if not issues:
        print("  no validator issues")
        return 0
    for issue in issues:
        rules = ", ".join(str(r.id) for r in getattr(issue, "rules", []))
        sev = getattr(getattr(issue, "severity", None), "name", "?")
        desc = getattr(issue, "description", "")
        print(f"  [{sev}] {type(issue).__name__}: {desc} ({rules})")
    return len(issues)


def compile_queries(collection: SigmaCollection) -> bool:
    from sigma.backends.elasticsearch import LuceneBackend

    backend = LuceneBackend()
    lucene = backend.convert(collection)
    print("  Lucene:")
    for q in lucene:
        print(f"    {q}")
    dsl = backend.convert(collection, output_format="dsl_lucene")
    print("  Elasticsearch DSL:")
    import json
    for d in dsl:
        for line in json.dumps(d, indent=2).splitlines():
            print(f"    {line}")
    return bool(lucene)


def main(argv: list[str]) -> int:
    path = Path(argv[0]) if argv else Path(RULE)
    if not path.exists():
        print(f"rule not found: {path}", file=sys.stderr)
        return 2

    print(f"== PARSE ({path}) ==")
    try:
        collection = parse(path)
    except Exception as exc:  # noqa: BLE001 - surface any pySigma parse error verbatim
        print(f"  PARSE FAILED: {type(exc).__name__}: {exc}")
        return 1

    print("== VALIDATE ==")
    error_issues = validate(collection)

    print("== COMPILE (Elasticsearch) ==")
    try:
        compiled = compile_queries(collection)
    except Exception as exc:  # noqa: BLE001 - a compile failure is a real result
        print(f"  COMPILE FAILED: {type(exc).__name__}: {exc}")
        compiled = False

    ok = compiled  # parse already succeeded; validator issues are advisory
    print("RESULT:", "PASS" if ok else "FAIL",
          f"(validator issues: {error_issues})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
