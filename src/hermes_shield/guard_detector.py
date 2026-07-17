"""Attach test evidence to surfaces (guard markers are attached during scan). Read-only."""
from __future__ import annotations
import re
from pathlib import Path
from .models import ActionSurface


def attach_test_evidence(surfaces, root: Path):
    """Cheap heuristic: map a surface's lane/file stem to test files that mention it.
    Looks in the TARGET repo's own conventional test dirs (root/tests, root/test, root/*/tests)."""
    test_index = {}
    candidates = [root / "tests", root / "test"]
    try:
        candidates += [d / "tests" for d in root.iterdir() if d.is_dir() and not d.name.startswith(".")]
    except OSError:
        pass
    for tests_dir in candidates:
        if not tests_dir.is_dir():
            continue
        for t in tests_dir.glob("test_*.py"):
            try:
                test_index[t.name] = t.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
    for s in surfaces:
        stem = Path(s.file_path).stem
        lane = s.likely_lane
        hits = [name for name, body in test_index.items()
                if stem in body or (lane and lane in body)]
        if hits:
            s.tests.test_files = hits[:4]
            s.tests.adversarial = any("adversarial" in h or "p2_8" in h for h in hits)
            s.tests.mutation = any("corpus" in h or "harness" in h for h in hits)
    return surfaces
