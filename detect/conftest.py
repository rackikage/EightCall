"""pytest configuration for detect.

`test_redact.py` and `test_livetail.py` are dual-mode: they run both as
standalone scripts (a homemade runner injects a temp `Path` as the first
positional argument, conventionally named `tmp`) and under pytest. Under pytest
that positional is resolved as a fixture, so this module provides a `tmp`
fixture that simply aliases the built-in `tmp_path`. Standalone execution does
not import pytest and is unaffected.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    """Alias for the built-in `tmp_path` fixture.

    Kept so the standalone test runners in `test_redact.py` / `test_livetail.py`
    (which call `fn(Path(tempdir))`) and pytest collection agree on the name.
    """
    return tmp_path
