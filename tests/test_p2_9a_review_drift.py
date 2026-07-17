#!/usr/bin/env python3
"""P2.9A-REVIEW — independent drift red-team. Builds a baseline from isolated fixtures, then applies
8 mutation scenarios to COPIES and asserts the drift detector catches each. No production edits, no
live actions."""
from __future__ import annotations
import shutil
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, baseline as BL, drift as DR


def _scan(root: Path):
    scan = repo_scanner.scan_repo(root)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return scan


def _seed(tmp: Path):
    # create_tweet pinned to line 4 so the surface id is stable across in-place edits
    (tmp / "poster.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def post():\n    assert_live_action_allowed({'surface':'x'})\n    client.create_tweet(text='x')\n")
    (tmp / "reader.py").write_text("def read(txt):\n    return summarize(article_text=txt)\n")
    return _scan(tmp)


def _baseline(tmp):
    return BL.build_baseline(_seed(tmp), "h0")


def test_01_guard_removal_detected(tmp_path):
    base = _baseline(tmp_path)
    # remove the guard but keep create_tweet on line 4 (stable id) so guard_removed is detectable
    (tmp_path / "poster.py").write_text(
        "# guard removed\n# was: kill switch check\ndef post():\n    client.create_tweet(text='x')\n")
    overall, findings = DR.diff(base, _scan(tmp_path))
    assert overall == "DRIFT_DETECTED"
    assert any(f.kind == "guard_removed" for f in findings), [f.kind for f in findings]


def test_02_content_change_detected(tmp_path):
    base = _baseline(tmp_path)
    # change the action body but keep it on line 4 (same id) -> fingerprint changes -> changed_surface
    (tmp_path / "poster.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def post():\n    assert_live_action_allowed({'surface':'x'})\n    client.create_tweet(text='COMPLETELY DIFFERENT BODY')\n")
    overall, findings = DR.diff(base, _scan(tmp_path))
    assert any(f.kind == "changed_surface" for f in findings), [f.kind for f in findings]


def test_03_new_action_surface_detected(tmp_path):
    base = _baseline(tmp_path)
    (tmp_path / "gmail.py").write_text("def send():\n    service.users().messages().send(userId='me',body={})\n")
    overall, findings = DR.diff(base, _scan(tmp_path))
    assert any(f.kind in ("new_live_action_surface", "new_surface") for f in findings)


def test_04_new_untrusted_ingress_detected(tmp_path):
    base = _baseline(tmp_path)
    (tmp_path / "src.py").write_text("def h(email_body):\n    return llm('reply to ' + email_body)\n")
    overall, findings = DR.diff(base, _scan(tmp_path))
    assert any(f.kind == "untrusted_ingress_added" for f in findings)


def test_05_dashboard_route_addition_detected(tmp_path):
    base = _baseline(tmp_path)
    (tmp_path / "dash.py").write_text("class H:\n    def do_POST(self):\n        apply(self.rfile.read(9))\n")
    overall, findings = DR.diff(base, _scan(tmp_path))
    assert overall == "DRIFT_DETECTED"
    assert any("dash.py" in f.surface_id for f in findings)


def test_06_queue_mutator_addition_detected(tmp_path):
    base = _baseline(tmp_path)
    (tmp_path / "q.py").write_text("def a(c):\n    c.execute(\"UPDATE x_post_queue SET status='x'\")\n")
    overall, findings = DR.diff(base, _scan(tmp_path))
    assert any("q.py" in f.surface_id for f in findings)


def test_07_no_drift_when_unchanged(tmp_path):
    base = _baseline(tmp_path)
    overall, findings = DR.diff(base, _scan(tmp_path))
    assert overall == "NO_DRIFT" and findings == []


def test_08_fence_removal_blocks(tmp_path):
    # baseline: fenced ingress; then remove the fence -> drift flags it
    (tmp_path / "ing.py").write_text(
        "from hermes_untrusted import make_untrusted_content\n"
        "def h(post_text):\n    return make_untrusted_content('x_post', post_text)\n")
    base = BL.build_baseline(_scan(tmp_path), "h0")
    (tmp_path / "ing.py").write_text("def h(post_text):\n    return llm('reply ' + post_text)\n")  # fence gone
    overall, findings = DR.diff(base, _scan(tmp_path))
    assert overall == "DRIFT_DETECTED"
    assert any(f.kind == "untrusted_fence_removed" for f in findings)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
