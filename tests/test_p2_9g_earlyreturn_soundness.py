#!/usr/bin/env python3
"""P2.9G — early-return guard soundness (independent-CTO-review fix). The `if <test>: return/raise`
guard must credit ONLY when the branch unconditionally exits (return/raise, not pass/continue) AND the
guard is the sole determinant of the branch (one call, no compound short-circuit). Read-only."""
from __future__ import annotations
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier  # noqa: E402

_KS = "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"


def _post_status(tmp, body):
    (tmp / "a.py").write_text(_KS + body)
    scan = repo_scanner.scan_repo(tmp)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    posts = [s for s in scan["surfaces"] if s.capability == "post"]
    return posts[0].guard_proof["status"] if posts else "no-surface"


def test_01_if_guard_pass_body_not_proven(tmp_path):
    # `if _ks(): pass` does NOT exit -> sink always runs -> must not be credited
    assert _post_status(tmp_path, "def f():\n    if _ks():\n        pass\n    client.create_tweet(text='x')\n") != "proven"


def test_02_compound_shortcircuit_not_proven(tmp_path):
    # `if not _ks() and other(): return` can fall through with the guard denied -> must not be credited
    assert _post_status(tmp_path, "def f():\n    if not _ks() and other():\n        return\n    client.create_tweet(text='x')\n") != "proven"


def test_03_continue_body_not_proven(tmp_path):
    # `if _ks(): continue` only skips a loop iteration -> does not dominate a straight-line sink
    assert _post_status(tmp_path, "def f():\n    for _ in range(1):\n        if _ks():\n            continue\n    client.create_tweet(text='x')\n") != "proven"


def test_04_sound_single_call_exit_still_proven(tmp_path):
    # `if not _ks(): return` -> single call, unconditional exit -> SOUND, still proven
    assert _post_status(tmp_path, "def f():\n    if not _ks():\n        return\n    client.create_tweet(text='x')\n") == "proven"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
