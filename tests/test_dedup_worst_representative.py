"""ROOT FIX regression (Fable-5 taint + destination axes): the dedup representative must be the
WORST/most-severe member of each (scope, cap, proof-status, guard-axis) partition — never merely the
textually-first sink.

Before the fix, repo_scanner partitioned each group and picked `target_group[0]` (the textually-first
sink) as the SOLE surface, folding the rest into sibling_sink_lines and DISCARDING their
taint / tainted_destination / dest_provenance signals. So a benign/untainted/constant-dest sink appearing
textually FIRST hid a genuinely reachable-unguarded-tainted sink of the SAME partition, collapsing the
customer-facing band to BLUE (taint axis) or AMBER (destination axis).

These probes reproduce both collapses (each must now be RED), keep the guard axis closed, and prove the fix
does not over-fire (an all-benign partition stays BLUE with unchanged counts).
"""
from hermes_shield import scan_hermes
from hermes_shield import install_report as IR


def _scan(tmp_path, files):
    for name, src in files.items():
        (tmp_path / name).write_text(src)
    return scan_hermes.run_scan(tmp_path)


def _scan_isolated(base_dir, files):
    """Scan `files` in a FRESH directory so the result is not polluted by sinks written into a shared
    tmp_path by an earlier _scan call (needed for a true single-file baseline)."""
    d = base_dir / "__iso__"
    d.mkdir(exist_ok=True)
    return _scan(d, files)


def _surfaces(scan, fname, cap):
    return [s for s in scan["surfaces"] if s.file_path == fname and s.capability == cap]


def _band(tmp_path, scan):
    rep = IR.build_report(tmp_path, scan)
    vb = IR.verdict_band(rep["non_gated_vulnerable"], rep["proven_live_poc"],
                         rep["install_liability_rce"], rep["reachable_amber_actions"],
                         rep["reachable_fixed_dest_review"])
    return rep, vb


# ───────────────────────── TAINT AXIS: untainted-first hides tainted exfil ─────────────────────────

def test_taint_axis_untainted_first_hides_tainted_sink_now_red(tmp_path):
    """THE taint-axis collapse: two same-capability DIRECT sinks in ONE function — an UNTAINTED constant
    call sorting textually FIRST, then a TAINTED call driven by an untrusted parameter. Both are
    subprocess_exec (a non-dest-aware RCE cap), same scope, same proof-status, same guard-axis, so the dedup
    folds them into one partition. The old first-wins representative was the UNTAINTED sink
    (EXPECTED_GUARD_MISSING, never counted red) — the tainted exfil's taint was discarded and the repo
    collapsed to BLUE. The worst-member representative now carries the taint, so the partition is RED."""
    scan = _scan(tmp_path, {"t.py":
        "import os\n"
        "def handler(payload):\n"
        "    os.system('uptime')\n"                     # untainted constant — textually FIRST
        "    os.system('grep ' + payload)\n"})          # tainted (untrusted param) — SECOND, the real exfil
    v = _surfaces(scan, "t.py", "subprocess_exec")
    assert v, "subprocess_exec sink not detected"
    # the surviving representative carries the taint of the worst member, not the benign first sink
    assert any(s.tainted_reachable for s in v), "the folded tainted sink's taint was discarded"
    assert any(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in v)
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1, "the tainted exfil was hidden behind the untainted first sink"
    assert vb["code"] == "red", "untainted-first must no longer collapse a tainted exfil to BLUE"


# ─────────────────── DESTINATION AXIS: constant-dest-first hides attacker-dest exfil ───────────────────

def test_dest_axis_constant_dest_first_hides_attacker_dest_now_red(tmp_path):
    """THE destination-axis collapse: two same-capability DIRECT sends in ONE function, both with TAINTED
    content — a CONSTANT-destination send sorting textually FIRST (which is legitimately demoted to the AMBER
    fixed-dest review band), then an UNKNOWN/attacker-controlled-destination send (a real exfil channel that
    must stay RED). Both are external_write, same scope/proof-status/guard-axis, so the dedup folds them into
    one partition. The old first-wins representative was the CONSTANT-dest send
    (CONFIG_DESTINATION_WRITE_REVIEW), so the repo banded AMBER and the attacker-dest exfil was silenced. The
    worst-member representative now carries the unknown-destination provenance, so the partition is RED."""
    scan = _scan(tmp_path, {"d.py":
        "import requests\n"
        "def relay(msg, dest):\n"                       # 'msg' tainted content; 'dest' attacker-controlled
        "    requests.post('https://ops.example.com/log', json={'data': msg})\n"   # constant dest — FIRST
        "    requests.post(dest, json={'data': msg})\n"})                          # unknown dest — SECOND
    v = _surfaces(scan, "d.py", "external_write")
    assert v, "external_write sink not detected"
    # the surviving representative carries the unknown (exfil-capable) destination, not the constant one
    assert any(s.dest_provenance == "unknown" for s in v), "the attacker-dest send's provenance was discarded"
    assert any(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in v)
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1, "the attacker-dest exfil was hidden behind the constant-dest send"
    assert vb["code"] == "red", "constant-dest-first must no longer collapse an attacker-dest exfil to AMBER"


# ───────────────────────── GUARD AXIS still closed (975a425 regression) ─────────────────────────

def test_guard_axis_unguarded_direct_after_guarded_wrapper_stays_red(tmp_path):
    """The worst-member representative selection must not reopen the guard axis (975a425): a kill-switch
    GUARDED wrapper call sorting textually first, then an UNGUARDED DIRECT sink of the same capability, must
    still surface the unguarded direct send as its OWN RED representative (the guardable/direct split keeps
    them in separate partitions; worst-member only reorders WITHIN a partition)."""
    scan = _scan(tmp_path, {"g.py":
        "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"
        "def send_draft(to_addr, body):\n"
        "    _ks({})\n"
        "    return service.users().messages().send(userId='me', body={'raw': body}).execute()\n"
        "def handler(body):\n"
        "    send_draft('a@b.com', body)\n"
        "    service.users().messages().send(userId='me', body={'raw': body}).execute()\n"})
    direct = [s for s in _surfaces(scan, "g.py", "email_send")
              if s.symbol == "handler" and s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"]
    assert direct, "the unguarded direct send was hidden behind the guarded wrapper (guard axis reopened)"
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1 and vb["code"] == "red"


# ───────────────────────── ANTI-OVER-FIRE: all-benign partition stays BLUE ─────────────────────────

def test_all_benign_partition_stays_blue_counts_unchanged(tmp_path):
    """No-over-fire anchor: a partition of ONLY benign (untainted, constant) sinks must NOT gain a false
    RED/AMBER, must still collapse to a SINGLE surface (counts unchanged vs per-sink), and the representative
    must remain the textually-first member (max() is tie-stable). A group of two untainted constant
    os.system() calls resolves BLUE, exactly as a single such call would."""
    scan = _scan(tmp_path, {"b.py":
        "import os\n"
        "def report():\n"
        "    os.system('uptime')\n"                     # untainted constant
        "    os.system('df -h')\n"})                    # untainted constant
    v = _surfaces(scan, "b.py", "subprocess_exec")
    assert v, "subprocess_exec sink not detected"
    # dedup still merges the same-partition siblings into a SINGLE representative (counts unchanged)
    assert len(v) == 1, "the benign partition must still collapse to one surface"
    assert not v[0].tainted_reachable                   # nothing tainted -> nothing to escalate
    assert v[0].sink_line == 3, "tie must keep the textually-first member as representative"
    assert all(s.verdict != "UNGUARDED_CRITICAL_LIVE_SINK" for s in v)

    # single-sink baseline: one untainted constant call yields the SAME (blue, zero-count) result.
    # Scan in an ISOLATED dir so the baseline is genuinely a single sink, not b.py's two sinks + b1.py.
    base = _scan_isolated(tmp_path, {"b1.py":
        "import os\n"
        "def report():\n"
        "    os.system('uptime')\n"})
    rep, vb = _band(tmp_path, scan)
    brep, bvb = _band(tmp_path, base)
    # the two-sink benign group bands IDENTICALLY to a single such sink — the second folded sibling adds no
    # false RED/AMBER (subprocess_exec is an RCE cap, so both band on install-liability, never a live threat).
    assert rep["non_gated_vulnerable"] == brep["non_gated_vulnerable"] == 0
    assert rep["reachable_amber_actions"] == brep["reachable_amber_actions"] == 0
    assert rep["reachable_fixed_dest_review"] == brep["reachable_fixed_dest_review"] == 0
    assert vb["code"] == bvb["code"], "the benign group must band exactly as the single-sink baseline"


# ─────────────── SHELL_FORM AXIS: non-shell (AMBER) sibling hides shell injection (RED) ───────────────

def _subprocess_band(tmp_path, src):
    scan = _scan(tmp_path, {"a.py": src})
    rep, vb = _band(tmp_path, scan)
    subs = _surfaces(scan, "a.py", "subprocess_exec")
    return scan, rep, vb, subs


def test_shell_form_axis_nonshell_first_hides_shell_injection_now_red(tmp_path):
    """THE shell_form-axis collapse (Fable-5 blocker): two same-scope subprocess_exec sinks, both driven by
    an untrusted parameter — a NON-shell subprocess.run([list]) (shell_form=False, legitimately AMBER
    SUBPROCESS_NON_SHELL_REVIEW) sorting textually FIRST, then an os.system(x) SHELL call (shell_form=True,
    RED command injection). Both are subprocess_exec and both dotted, so before the fix they folded into ONE
    guardable-axis partition; the taint/dest severity tuple tied (dest axes homogeneous for this non-dest-aware
    RCE cap), so the textually-first AMBER non-shell sink hid the RED shell injection -> ngv=0, band AMBER. The
    shell_form partition key now keeps each form's OWN representative and verdict."""
    scan, rep, vb, subs = _subprocess_band(
        tmp_path,
        "def handle_task(payload):\n"
        "    import subprocess, os\n"
        "    subprocess.run(['echo', payload])\n"   # shell_form=False -> AMBER, textually FIRST
        "    os.system(payload)\n")                 # shell_form=True  -> RED injection, SECOND
    assert any(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in subs), \
        "the RED shell command-injection sink was hidden behind the non-shell AMBER sibling"
    assert any(s.verdict == "SUBPROCESS_NON_SHELL_REVIEW" for s in subs), \
        "the non-shell sink must keep its own AMBER verdict (not be dropped by the split)"
    assert rep["non_gated_vulnerable"] >= 1
    assert vb["code"] == "red", "non-shell-first must no longer collapse a shell injection to AMBER"


def test_shell_form_axis_is_order_independent(tmp_path):
    """The shell/non-shell verdict split must not depend on source order: os.system(x) first then
    subprocess.run([list]) must band identically to the reverse. Both orders yield exactly one RED
    injection (ngv>=1, red)."""
    fwd, rep_f, vb_f, _ = _subprocess_band(
        tmp_path,
        "def h(payload):\n"
        "    import subprocess, os\n"
        "    os.system(payload)\n"
        "    subprocess.run(['echo', payload])\n")
    rev, rep_r, vb_r, _ = _subprocess_band(
        tmp_path,
        "def h(payload):\n"
        "    import subprocess, os\n"
        "    subprocess.run(['echo', payload])\n"
        "    os.system(payload)\n")
    assert vb_f["code"] == vb_r["code"] == "red"
    assert rep_f["non_gated_vulnerable"] == rep_r["non_gated_vulnerable"] >= 1


# ─────────── EVIDENCE TRAIL: sibling_sink_lines excludes the chosen representative ───────────

def test_sibling_sink_lines_exclude_chosen_representative(tmp_path):
    """Fable-5 evidence-trail defect: when max() picks a LATER (worst) member as the representative,
    sibling_sink_lines must list the OTHER folded members (here the untainted first sink), never the
    representative's own line — and must not drop the first member's line. The old target_group[1:] slice
    listed the representative as its own sibling and lost the textually-first line."""
    scan = _scan(tmp_path, {"s.py":
        "import os\n"
        "def handler(payload):\n"
        "    os.system('uptime')\n"              # line 3 untainted -> folded sibling
        "    os.system('grep ' + payload)\n"})   # line 4 tainted   -> chosen (worst) representative
    reps = [s for s in _surfaces(scan, "s.py", "subprocess_exec")
            if s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"]
    assert reps, "the tainted worst member must be the representative"
    rep = reps[0]
    assert rep.sink_line == 4, "worst-member selection must pick the later tainted sink"
    sibs = rep.guard_proof.get("sibling_sink_lines")
    assert sibs == [3], f"siblings must be the folded first member [3], got {sibs}"
    assert rep.sink_line not in sibs, "the representative must never be listed as its own sibling"
