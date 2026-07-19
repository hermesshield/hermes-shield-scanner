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


def _band(root, scan):
    """The canonical antivirus banner band for a built report (RED/AMBER/BLUE — same fn the HTML + CLI use)."""
    r = IR.build_report(root, scan)
    return IR.verdict_band(r["non_gated_vulnerable"], r["proven_live_poc"], r["install_liability_rce"],
                           r["reachable_amber_actions"], r["reachable_fixed_dest_review"],
                           r["reachability_unknown"], nothing_scanned=r["nothing_scanned"]), r


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


# ---- HOLE 1 (Fable-5 re-run) — assign-consumed-exit must respect statement ORDER --------------------
def test_H1_assign_guard_consumed_AFTER_sink_stays_red(tmp_path):
    # cmd -> assigned gate -> SINK runs UNCONDITIONALLY -> consuming `if not ok: raise` is AFTER the sink.
    # The sink was already executed before any check, so the late branch must NOT credit it. RED.
    (tmp_path / "app.py").write_text(
        "from final_action_gate import allow_action\n"
        "def handle_reply(cmd):\n"
        "    ok = allow_action(cmd)\n"       # recognised gate, decision assigned
        "    eval(cmd)\n"                    # SINK — runs before any check
        "    if not ok:\n        raise RuntimeError('blocked')\n")   # consuming exit AFTER the sink
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") != "proven"           # not credited
    assert s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"        # RED
    assert IR.is_non_gated_vulnerable(s)


def test_H1_assign_guard_consumed_BEFORE_sink_still_downgrades(tmp_path):
    # the genuine ordering: assign -> consuming early-exit -> THEN the sink. The gate dominates -> downgraded.
    (tmp_path / "app.py").write_text(
        "from final_action_gate import allow_action\n"
        "def handle_reply(cmd):\n"
        "    ok = allow_action(cmd)\n"
        "    if not ok:\n        return None\n"    # consuming exit BEFORE the sink
        "    eval(cmd)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") == "proven"
    assert not IR.is_non_gated_vulnerable(s)


# ---- HOLE 2 (Fable-5 re-run) — assert-form must be UNCONDITIONALLY evaluated ------------------------
def test_H2_assert_shortcircuit_operand_not_credited(tmp_path):
    # `assert cmd or allow_action(cmd)` — when cmd is truthy the guard never runs (short-circuit). No credit.
    (tmp_path / "app.py").write_text(
        "from final_action_gate import allow_action\n"
        "def handle_reply(cmd):\n"
        "    assert cmd or allow_action(cmd)\n"
        "    eval(cmd)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") != "proven"
    assert s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"       # RED
    assert IR.is_non_gated_vulnerable(s)


def test_H2_assert_tautology_not_credited(tmp_path):
    # `assert allow_action(cmd) or True` — a tautology; the assert can never fire. No credit.
    (tmp_path / "app.py").write_text(
        "from final_action_gate import allow_action\n"
        "def handle_reply(cmd):\n"
        "    assert allow_action(cmd) or True\n"
        "    eval(cmd)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") != "proven"
    assert s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"       # RED
    assert IR.is_non_gated_vulnerable(s)


def test_H2_genuine_assert_guard_still_downgrades(tmp_path):
    # `assert allow_action(cmd)` — the guard IS the sole, unconditionally-evaluated operand -> credited.
    (tmp_path / "app.py").write_text(
        "from shield_kill_switch import assert_live_action_allowed\n"
        "def handle_reply(cmd):\n"
        "    assert assert_live_action_allowed(cmd)\n"
        "    eval(cmd)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") == "proven"
    assert not IR.is_non_gated_vulnerable(s)


# ---- MUST-NOT-OVER-CORRECT — the already-correct behaviours must be unchanged ----------------------
def test_MSC_if_guard_after_sink_stays_red(tmp_path):
    # `eval(cmd); if not allow_action(cmd): return` — the if-form guard is AFTER the sink -> RED (unchanged).
    (tmp_path / "app.py").write_text(
        "from final_action_gate import allow_action\n"
        "def handle_reply(cmd):\n"
        "    eval(cmd)\n"
        "    if not allow_action(cmd):\n        return None\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") != "proven"
    assert s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"
    assert IR.is_non_gated_vulnerable(s)


def test_MSC_if_not_guard_return_still_downgrades(tmp_path):
    # `if not allow_action(cmd): return` then the sink — the canonical early-return gate -> downgraded.
    (tmp_path / "app.py").write_text(
        "from shield_kill_switch import allow_action\n"
        "def handle_reply(cmd):\n"
        "    if not allow_action(cmd):\n        return None\n"
        "    eval(cmd)\n")
    s = _sink(_scan(tmp_path))
    assert s.guard_proof.get("status") == "proven"
    assert not IR.is_non_gated_vulnerable(s)


# ---- SHIP-BLOCKER 2 (Fable-5 re-run) — silent site-packages/vendored footgun fails LOUD --------------
def test_FOOTGUN_all_vendored_fails_loud_not_green(tmp_path):
    # A real RCE, but the ONLY files live under a dependency/vendored dir the scanner skips. Today this
    # emitted an empty GREEN report (0 files -> no findings -> silent "safe"). It must FAIL LOUD instead.
    vend = tmp_path / "site-packages" / "evil"
    vend.mkdir(parents=True)
    (vend / "mod.py").write_text(
        "def handle(cmd):\n"
        "    eval(cmd)\n")
    scan = _scan(tmp_path)
    assert scan["files_scanned"] == 0                        # nothing was analysed
    band, r = _band(tmp_path, scan)
    assert r["nothing_scanned"] is True
    assert r["nothing_scanned_reason"] == "all_skipped_vendored"
    assert band["code"] != "blue"                            # NON-green: never a silent PASS
    assert "0 files analysed" in band["head"]
    md = IR.render(r)
    assert "NOTHING SCANNED" in md


def test_FOOTGUN_empty_tree_fails_loud_not_green(tmp_path):
    # No scannable source at all -> still a non-scan, still fails loud (never a clean bill).
    (tmp_path / "README.md").write_text("# docs only\n")
    scan = _scan(tmp_path)
    assert scan["files_scanned"] == 0
    band, r = _band(tmp_path, scan)
    assert r["nothing_scanned"] is True
    assert band["code"] != "blue"


def test_FOOTGUN_clean_real_repo_still_reads_clean(tmp_path):
    # MUST-NOT-OVER-CORRECT: a genuinely-clean REAL source repo (>0 files, no dangerous sink) is NOT a
    # footgun — it scans normally and reads clean (blue), with no "nothing scanned" warning.
    (tmp_path / "app.py").write_text(
        "def add(a, b):\n"
        "    return a + b\n"
        "def greet(name):\n"
        "    return 'hello ' + str(name)\n")
    scan = _scan(tmp_path)
    assert scan["files_scanned"] >= 1                        # real source was analysed
    band, r = _band(tmp_path, scan)
    assert r["nothing_scanned"] is False                     # NOT a false footgun warning
    assert band["code"] == "blue"                            # clean reads clean
    assert r["non_gated_vulnerable"] == 0


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
