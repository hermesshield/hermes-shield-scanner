#!/usr/bin/env python3
"""Stage 1.5 — guard-integrity v0.2 (rebuilt after adversarial audit). The checker makes a HIGH-
confidence claim ONLY that a guard is a no-op / fail-open (GUARD_NOOP_CONFIRMED / FAIL_OPEN_SUSPECT);
anything that merely looks like a gate is GUARD_BLOCK_SHAPED_UNVERIFIED (review-required, never
certified). Includes the skeptic's own bypasses as regression cases. Read-only."""
from __future__ import annotations
import ast
import sys
from pathlib import Path


from hermes_shield import guard_integrity as GI  # noqa: E402


def _v(src):
    fn = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)][0]
    return GI._verdict(GI._analyse_fn(fn))


# ---- high-confidence NO-OP / FAIL-OPEN catches (these downgrade + BLOCK) --------------------
def test_01_return_true_noop():
    assert _v("def g(ctx=None):\n    return True\n")[0] == "GUARD_NOOP_CONFIRMED"


def test_02_pass_noop():
    assert _v("def g(ctx=None):\n    pass\n")[0] == "GUARD_NOOP_CONFIRMED"


def test_03_log_and_continue_is_noop():
    # skeptic #4: returns None on both paths -> cannot block
    assert _v("def g(x):\n    if not ok(x):\n        log('blocked')\n        return\n    return\n")[0] == "GUARD_NOOP_CONFIRMED"


def test_04_dead_code_raise_is_noop():
    # skeptic #6: raise after unconditional return is unreachable -> not a block path
    assert _v("def g():\n    return True\n    raise RuntimeError('x')\n")[0] == "GUARD_NOOP_CONFIRMED"


def test_05_fail_open_bare_except_pass():
    assert _v("def g():\n    try:\n        if x():\n            raise Blocked()\n    except Exception:\n        pass\n")[0] == "GUARD_FAIL_OPEN_SUSPECT"


def test_06_fail_open_except_returns():
    # skeptic #3: except that RETURNS (not pass) still swallows the block -> fail-open
    assert _v("def g():\n    try:\n        raise Blocked()\n    except Exception:\n        return True\n")[0] == "GUARD_FAIL_OPEN_SUSPECT"


# ---- honest 'looks like a gate but unverified' (review-required, NOT a clean pass) ----------
def test_07_input_validation_raise_is_unverified_not_clean():
    # skeptic #1: input-validation raise + return True. v0 wrongly called this HAS_BLOCK_PATH (safe).
    # v0.2 must NOT confidently pass it -> block-shaped-UNVERIFIED (a human must review).
    assert _v("def g(action):\n    if action is None:\n        raise ValueError('no action')\n    return True\n")[0] == "GUARD_BLOCK_SHAPED_UNVERIFIED"


def test_08_inverted_polarity_is_unverified_not_clean():
    # skeptic #2: `if allowed(): raise` (inverted). We cannot resolve polarity -> must not certify.
    assert _v("def g(x):\n    if allowed(x):\n        raise RuntimeError('nope')\n    return True\n")[0] == "GUARD_BLOCK_SHAPED_UNVERIFIED"


def test_09_real_raise_gate_is_unverified_not_certified():
    # even a genuine-looking raise gate is only 'block-shaped, unverified' — we never claim it works
    assert _v("def g(x):\n    if bad(x):\n        raise Blocked()\n")[0] == "GUARD_BLOCK_SHAPED_UNVERIFIED"


def test_10_assert_gate_not_false_flagged():
    # skeptic false-positive: assert is a real block, must not be NOOP
    assert _v("def g(x):\n    assert ok(x), 'blocked'\n")[0] == "GUARD_BLOCK_SHAPED_UNVERIFIED"


def test_11_sysexit_gate_not_false_flagged():
    assert _v("import sys\ndef g(x):\n    if not ok(x):\n        sys.exit(1)\n")[0] == "GUARD_BLOCK_SHAPED_UNVERIFIED"


def test_12_delegation_not_false_flagged_as_noop():
    # skeptic false-positive: `return _real_gate(x)` delegates; must not be NOOP_CONFIRMED
    v, flags = _v("def g(x):\n    return _real_gate(x)\n")
    assert v == "GUARD_BLOCK_SHAPED_UNVERIFIED" and "DELEGATES_TO_CALLEE" in flags


def test_13_mutable_input_flagged():
    _, flags = _v("import os\ndef g():\n    if os.environ.get('K'):\n        raise Blocked()\n")
    assert "CONTROL_INPUT_MUTABLE" in flags


def test_16_unresolved_guard_requires_review_not_silent_pass(tmp_path):
    from hermes_shield import repo_scanner, surface_classifier
    # guard defined as a LAMBDA -> _find_def can't see it -> UNRESOLVED -> must require review, not pass
    (tmp_path / "hermes_global_kill_switch.py").write_text("assert_live_action_allowed = lambda ctx=None: None\n")
    (tmp_path / "poster.py").write_text(
        "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"
        "def post():\n    try:\n        _ks({})\n    except Exception:\n        raise\n    client.create_tweet(text='x')\n")
    scan = repo_scanner.scan_repo(tmp_path)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    GI.build.cache_clear()
    GI.annotate(tmp_path, scan["surfaces"])
    post = next((s for s in scan["surfaces"] if s.capability == "post"), None)
    assert post and post.guard_proof.get("integrity_review_required") is True


def test_17_noop_stub_downgrades_surface_to_suspect(tmp_path):
    from hermes_shield import repo_scanner, surface_classifier
    (tmp_path / "hermes_global_kill_switch.py").write_text("def assert_live_action_allowed(context=None):\n    return True\n")
    (tmp_path / "poster.py").write_text(
        "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"
        "def post():\n    try:\n        _ks({})\n    except Exception:\n        raise\n    client.create_tweet(text='x')\n")
    scan = repo_scanner.scan_repo(tmp_path)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    GI.build.cache_clear()
    GI.annotate(tmp_path, scan["surfaces"])
    post = next((s for s in scan["surfaces"] if s.capability == "post"), None)
    assert post and post.verdict == "GUARD_INTEGRITY_SUSPECT"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
