#!/usr/bin/env python3
"""Pins the anti-inflation discipline of the recall scorer (Fable-5 recall audit).

The headline recall must count sinks the scanner actually LOCATED, not locality
coincidences. Two guarantees are pinned here:

1. No span bleed — a planted row must never be credited to a NEIGHBOURING
   surface via that surface's enclosing-function span (line_start/line_end).
   Matching anchors on the true sink line only.
2. One surface, one row — a single detected surface can be credited to at most
   one planted row, so one located sink cannot satisfy two distinct planted sinks.

Together these make the reported number honest: the corpus scores 18/21 (85.7%),
not the inflated 20/21 (95.2%) that the old ±3-line span-inclusive matcher gave.
Read-only; drives the scorer's pure functions directly. No subprocess, no scan."""
from __future__ import annotations

import json
import sys
from pathlib import Path

_CORPUS = Path(__file__).resolve().parent / "recall_corpus"
if str(_CORPUS) not in sys.path:
    sys.path.insert(0, str(_CORPUS))

import score  # noqa: E402


def test_surface_lines_anchors_on_sink_line_not_span():
    # A surface whose call site is line 28 but whose function spans 23..28 must
    # expose ONLY the sink anchor (28), never the span edges (23), so a planted
    # row at line 20 cannot reach it within +/-3.
    s = {"file_path": "tools.py", "sink_line": 28, "line_start": 23,
         "line_end": 28, "id": "tools.py:28:dynamic_dispatch"}
    assert score.surface_lines(s) == {28}


def test_span_used_only_as_fallback_when_no_sink_anchor():
    # Defensive: a surface with no sink_line and no id-embedded line falls back
    # to the span, so it is still scorable.
    s = {"file_path": "x.py", "line_start": 40, "line_end": 44}
    assert score.surface_lines(s) == {40, 44}


def test_no_locality_bleed_onto_neighbour_span():
    # Reproduces the tools.py inflation: planted S02 (line 20, cross-file exec
    # re-export the engine does NOT resolve) and S03 (line 28, genuinely caught).
    # Only ONE surface exists, at sink line 28. S02 must be a MISS; S03 caught.
    rows = [{"repo": "r", "file": "tools.py", "line": 20},
            {"repo": "r", "file": "tools.py", "line": 28}]
    surfaces = [{"file_path": "tools.py", "sink_line": 28, "line_start": 23,
                 "line_end": 28, "id": "tools.py:28:dynamic_dispatch"}]
    assigned = score.match_recall(rows, surfaces, tol=3)
    assert set(assigned) == {1}                 # only the line-28 row is credited
    assert assigned[1]["sink_line"] == 28


def test_one_surface_cannot_satisfy_two_rows():
    # Two planted rows both within tol of a SINGLE surface: exactly one wins
    # (the closest), the other is a genuine miss. Prevents double-credit.
    rows = [{"repo": "r", "file": "f.py", "line": 10},
            {"repo": "r", "file": "f.py", "line": 12}]
    surfaces = [{"file_path": "f.py", "sink_line": 12, "id": "f.py:12:x"}]
    assigned = score.match_recall(rows, surfaces, tol=3)
    assert set(assigned) == {1}                 # line 12 (dist 0) wins over line 10 (dist 2)


def test_corpus_static_recall_is_18_of_21_no_inflation():
    # End-to-end against the committed static scan: the honest number of record
    # is 18/21, and the three residuals are exactly the genuine misses. Guards
    # against the 20/21 (95.2%) inflation ever returning.
    sc = _CORPUS / "scan_out_static"
    if not (sc / "agent_tool_runner" / "outputs"
            / "hermes_action_surface_scan.json").is_file():
        import pytest
        pytest.skip("scan_out_static not generated in this checkout")
    manifest = json.load(open(_CORPUS / "MANIFEST.json"))
    planted = [r for r in manifest["planted"] if r.get("reachable")]
    repos = sorted({r["repo"] for r in planted})
    caught, missed = 0, []
    for repo in repos:
        surf = score.load_surfaces(str(sc), repo) or []
        rows = [r for r in planted if r["repo"] == repo]
        assigned = score.match_recall(rows, surf, tol=3)
        caught += len(assigned)
        missed += [f"{r['file']}:{r['line']}"
                   for i, r in enumerate(rows) if i not in assigned]
    assert (caught, len(planted)) == (18, 21)
    assert set(missed) == {"tools.py:20", "senders.py:18", "loader.py:19"}

    # And the default-tolerance number must equal the tol-0 truth (no bleed):
    caught_t0 = 0
    for repo in repos:
        surf = score.load_surfaces(str(sc), repo) or []
        rows = [r for r in planted if r["repo"] == repo]
        caught_t0 += len(score.match_recall(rows, surf, tol=0))
    assert caught_t0 == caught
