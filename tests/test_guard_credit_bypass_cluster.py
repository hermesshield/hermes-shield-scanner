#!/usr/bin/env python3
"""Guard-credit bypass cluster (Fable-5 CONFIRMED) — the scanner credited guards that provide zero real
protection, downgrading a live RCE from RED to AMBER/protected. Four holes, one guiding principle: a guard
may only DOWNGRADE a tainted critical sink when its control value is CONSUMED, it plausibly inspects the
SAME tainted variable the sink consumes, and the proof holds WHOLE-PROGRAM.

  A) NO-OP GUARD          — a bare return-based guard call whose boolean is DISCARDED is not a gate.
  B) INTEGRITY RE-ESCALATE— a provable discarded-return no-op re-escalates to BLOCK, not stays AMBER.
  C) WRONG-VARIABLE GUARD — a guard inspecting a DIFFERENT variable than the sink consumes is not credited.
  D) CROSS-FILE ALT PATH  — an in-file-only wrapper proof never overrides a reachable unguarded cross-file
                            path; the sink stays RED/non-gated.

MUST NOT OVER-CORRECT: a genuine guard (consumed AND gates the tainted var AND whole-program dominant)
still downgrades correctly. Read-only; static.
"""
from __future__ import annotations
import ast
import sys
from pathlib import Path

from hermes_shield import scan_hermes, install_report as IR, guard_integrity as GI  # noqa: E402


def _scan(root):
    return scan_hermes.run_scan(root)


def _sink(scan, cap="code_exec"):
    hits = [s for s in scan["surfaces"] if s.capability == cap]
    assert hits, f"no {cap} surface found"
    return hits[0]


# ---- A) bare return-based no-op guard is NOT credited; sink stays RED ------------------------------
def test_A_bare_returnbased_killswitch_not_credited(tmp_path):
    (tmp_path / "app.py").write_text(
        "from shield_kill_switch import live_actions_blocked\n"
        "def handle_reply(text):\n"
        "    live_actions_blocked()\n"          # bare — boolean DISCARDED (no-op)
        "    return eval(text)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") != "proven"           # not credited
    assert s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"        # RED
    assert IR.is_non_gated_vulnerable(s)


def test_A_bare_raise_style_gate_still_credited(tmp_path):
    # a raise-style (side-effect) gate called bare IS a real gate — the abort is the protection.
    (tmp_path / "app.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def publish():\n"
        "    assert_live_action_allowed({'surface': 'x'})\n"
        "    client.create_tweet(text='x')\n")
    posts = [s for s in _scan(tmp_path)["surfaces"] if s.capability == "post"]
    assert posts and posts[0].guard_proof.get("status") == "proven"
    assert posts[0].guard_proof.get("proof_type") == "same_function_before_sink"


def test_A_unused_assignment_guard_not_credited(tmp_path):
    (tmp_path / "app.py").write_text(
        "from final_action_gate import allow_action\n"
        "def handle_reply(text):\n"
        "    flag = allow_action()\n"           # assigned but never branched on -> no-op
        "    return eval(text)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") != "proven"
    assert IR.is_non_gated_vulnerable(s)


def test_A_assign_then_branch_is_credited(tmp_path):
    # a consumed assignment (assign then early-exit branch) DOES gate -> downgraded, not RED.
    (tmp_path / "app.py").write_text(
        "from final_action_gate import allow_action\n"
        "def handle_reply(text):\n"
        "    flag = allow_action()\n"
        "    if not flag:\n        return None\n"
        "    return eval(text)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") == "proven"
    assert not IR.is_non_gated_vulnerable(s)


# ---- B) provable discarded-return no-op re-escalates to BLOCK (guard-integrity) --------------------
def test_B_discarded_returnbased_decoy_reescalates_to_block(tmp_path):
    # a bare raise-NAMED guard whose DEFINITION actually RETURNS a bool (no raise). fix A credits the bare
    # call on the raise-assumption; guard_integrity re-checks the def, finds it return-based + discarded,
    # and re-escalates the provable no-op to BLOCK (verify-manually), never a soft AMBER review.
    (tmp_path / "hermes_global_kill_switch.py").write_text(
        "import os\n"
        "def assert_live_action_allowed(surface):\n"
        "    return os.environ.get('LIVE_OK') == '1'\n")   # RETURN-based decoy, never raises
    (tmp_path / "app.py").write_text(
        "from hermes_global_kill_switch import assert_live_action_allowed\n"
        "def handle_reply(text):\n"
        "    assert_live_action_allowed({'surface': 'x'})\n"
        "    return eval(text)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("guard_return_consumed") is False
    assert s.verdict == "GUARD_INTEGRITY_SUSPECT"            # re-escalated, not review
    assert s.live_promotion_verdict == "BLOCK"


def test_B_consumed_returnbased_guard_not_reescalated(tmp_path):
    # the SAME return-based def, but its result is genuinely CONSUMED (if not ...: raise) -> honest review,
    # NOT re-escalated to BLOCK (it is a real, consumed gate).
    (tmp_path / "final_action_gate.py").write_text(
        "import os\n"
        "def allow_action():\n"
        "    return os.environ.get('LIVE_OK') == '1'\n")
    (tmp_path / "app.py").write_text(
        "from final_action_gate import allow_action\n"
        "def handle_reply(text):\n"
        "    if not allow_action():\n        raise RuntimeError('blocked')\n"
        "    return eval(text)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("guard_return_consumed") is True
    assert s.verdict != "GUARD_INTEGRITY_SUSPECT"           # a consumed gate is not a no-op
    assert not IR.is_non_gated_vulnerable(s)


# ---- C) wrong-variable guard is not credited; action-level zero-arg gate IS -----------------------
def test_C_wrong_variable_guard_not_credited(tmp_path):
    (tmp_path / "app.py").write_text(
        "from final_action_gate import allow_action\n"
        "def handle_reply(text, user_id):\n"
        "    if not allow_action(user_id):\n        return None\n"   # inspects user_id, not text
        "    return eval(text)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") != "proven"
    assert s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"       # RED — not counted protected
    assert IR.is_non_gated_vulnerable(s)


def test_C_genuine_action_level_gate_downgrades(tmp_path):
    (tmp_path / "app.py").write_text(
        "from shield_kill_switch import allow_action\n"
        "def handle_reply(text):\n"
        "    if not allow_action():\n        raise RuntimeError('blocked')\n"   # zero-arg action gate
        "    return eval(text)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") == "proven"
    assert not IR.is_non_gated_vulnerable(s)                 # genuinely downgraded


def test_C_content_guard_on_sink_var_downgrades(tmp_path):
    # a guard that DOES inspect the sink's tainted variable is a real content gate -> credited.
    (tmp_path / "app.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def handle_reply(text):\n"
        "    if not assert_live_action_allowed(text):\n        return None\n"
        "    return eval(text)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") == "proven"


# ---- D) cross-file alternate unguarded path keeps the sink RED ------------------------------------
def test_D_crossfile_alternate_path_stays_red(tmp_path):
    (tmp_path / "core.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def _run_action(text):\n"
        "    return eval(text)\n"
        "def guarded_caller(text):\n"
        "    assert_live_action_allowed({'surface': 'x'})\n"
        "    return _run_action(text)\n")
    (tmp_path / "entry.py").write_text(
        "from core import _run_action\n"
        "def entry_open(text):\n"
        "    return _run_action(text)\n")            # UNGUARDED cross-file path
    s = _sink(_scan(tmp_path))
    assert s.guard_attribution.get("critical_guard_on_path") in ("partial", "no")
    assert s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"       # RED, not downgraded by in-file proof
    assert IR.is_non_gated_vulnerable(s)


def test_D_all_paths_guarded_downgrades(tmp_path):
    # every caller (in-file AND cross-file) is guarded -> whole-program protected -> downgraded, not RED.
    (tmp_path / "core.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def _run_action(text):\n"
        "    return eval(text)\n"
        "def guarded_caller(text):\n"
        "    assert_live_action_allowed({'surface': 'x'})\n"
        "    return _run_action(text)\n")
    (tmp_path / "entry.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "from core import _run_action\n"
        "def entry_open(text):\n"
        "    assert_live_action_allowed({'surface': 'y'})\n"
        "    return _run_action(text)\n")
    s = _sink(_scan(tmp_path))
    assert not IR.is_non_gated_vulnerable(s)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
