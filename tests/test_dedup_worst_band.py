"""STRUCTURAL REDESIGN regression (Fable-5 dedup band-suppression class — 5th/6th-axis closure).

The dedup representative used to be chosen by a PRE-VERDICT severity proxy (repo_scanner._sink_severity,
which ranks only taint + destination). Any verdict-determining input the proxy could not see was a latent
hole: a benign representative could hide a band-driving sibling of the same (scope, cap) partition and lower
the customer band (RED/AMBER/BLUE). The whack-a-mole axes fixed by adding partition keys (guard-wrapper,
shell_form) or by the taint/dest proxy were only the ones someone had already found.

The redesign closes the CLASS: repo_scanner emits a full surface for every raw sink of a partition, and
install_report.collapse_dedup_to_worst_band folds each partition — AFTER the verdict pipeline — to the
WORST-BANDED member. The survivor therefore drives the max band over ALL raw members on EVERY axis, so a
folded sibling can never lower the band, independent of which sink is the display representative.

Two layers of proof:
  1. END-TO-END, the REPRODUCED 5th axis (guard STRENGTH vs proof-identity): a LOCAL_DEFINITION decoy-guarded
     RED sink shares the 'proven' partition with a kill-switch-guarded REVIEW sibling; the proxy folded the
     RED sink behind the guarded sibling (blue). It must now stay RED.
  2. UNIT, the collapse invariant itself, parametrised across taint / destination / shell / guard-strength /
     context(mutating) — the survivor's band == the max band over all raw members, one row per partition.
"""
import pytest

from hermes_shield import scan_hermes
from hermes_shield import install_report as IR


# ───────────────────────────── 1. END-TO-END: guard-STRENGTH axis ─────────────────────────────

def _scan(tmp_path, files):
    for name, src in files.items():
        (tmp_path / name).write_text(src)
    return scan_hermes.run_scan(tmp_path)


def _surfaces(scan, fname, cap):
    return [s for s in scan["surfaces"] if s.file_path == fname and s.capability == cap]


def _band(tmp_path, scan):
    rep = IR.build_report(tmp_path, scan)
    vb = IR.verdict_band(rep["non_gated_vulnerable"], rep["proven_live_poc"],
                         rep["install_liability_rce"], rep["reachable_amber_actions"],
                         rep["reachable_fixed_dest_review"])
    return rep, vb


# A = decoy-guarded (LOCAL_DEFINITION) external_write, tainted content, UNKNOWN non-tainted dest -> RED.
# B = kill-switch-guarded (RESOLVED_IMPORT) external_write, tainted content AND tainted dest -> downgraded.
# fg.prove() counts A's local decoy as 'proven', so A and B share the SAME 'proven'/dotted/shell partition;
# _sink_severity ranks B (1,1,2) above A (1,0,2) and folded A behind the guarded (blue) sibling -> ngv 0.
_A_FIRST = (
    "import requests, flask\n"
    "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"
    "def assert_action_allowed():\n"
    "    return True\n"
    "def pick_url():\n"
    "    return CFG\n"
    "def handler():\n"
    "    msg = flask.request.args.get('m')\n"
    "    dest = flask.request.args.get('to')\n"
    "    assert_action_allowed()\n"                       # local decoy before A
    "    url = pick_url()\n"                              # unknown, non-tainted dest for A
    "    requests.post(url, json={'data': msg})\n"        # A: decoy-guarded RED
    "    _ks({})\n"                                        # real kill-switch before B
    "    requests.post(dest, json={'data': msg})\n")       # B: guarded, tainted dest

# B textually first (the worst-_sink_severity member sorts first) — proves order-independence.
_B_FIRST = (
    "import requests, flask\n"
    "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"
    "def assert_action_allowed():\n"
    "    return True\n"
    "def pick_url():\n"
    "    return CFG\n"
    "def handler():\n"
    "    msg = flask.request.args.get('m')\n"
    "    dest = flask.request.args.get('to')\n"
    "    _ks({})\n"                                        # real kill-switch before B
    "    requests.post(dest, json={'data': msg})\n"        # B: guarded, tainted dest (worst proxy tuple)
    "    assert_action_allowed()\n"                       # local decoy before A
    "    url = pick_url()\n"                              # unknown, non-tainted dest for A
    "    requests.post(url, json={'data': msg})\n")        # A: decoy-guarded RED


def test_guard_strength_decoy_guarded_red_solo_is_red(tmp_path):
    """Control: the decoy-guarded RED sink A ALONE bands RED — the scanner correctly rejects the
    LOCAL_DEFINITION decoy for a lone sink (MED-1)."""
    solo = (
        "import requests, flask\n"
        "def assert_action_allowed():\n"
        "    return True\n"
        "def pick_url():\n"
        "    return CFG\n"
        "def handler():\n"
        "    msg = flask.request.args.get('m')\n"
        "    assert_action_allowed()\n"
        "    url = pick_url()\n"
        "    requests.post(url, json={'data': msg})\n")
    scan = _scan(tmp_path, {"solo.py": solo})
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1 and vb["code"] == "red"


@pytest.mark.parametrize("order,src", [("A_first", _A_FIRST), ("B_first", _B_FIRST)])
def test_guard_strength_decoy_red_not_hidden_by_real_guard(tmp_path, order, src):
    """THE reproduced 5th axis: a decoy-guarded RED sink must NOT be folded behind a critically-guarded
    sibling of the same 'proven' partition. The worst-BANDED collapse surfaces the RED sink regardless of
    source order — the guarded sibling (higher taint/dest proxy tuple) can no longer win the display row and
    silence the exfil."""
    scan = _scan(tmp_path, {"p.py": src})
    v = _surfaces(scan, "p.py", "external_write")
    assert any(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in v), \
        f"[{order}] the decoy-guarded RED sink was hidden behind the real-guarded sibling"
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1, f"[{order}] the RED exfil was hidden -> ngv under-counted"
    assert vb["code"] == "red", f"[{order}] a folded sibling lowered the band to {vb['code']}"


def test_guard_strength_partition_still_collapses_to_one_row(tmp_path):
    """No over-count: despite two raw external_write sinks in one function/partition, the customer display
    still shows ONE row for the partition (the worst-banded survivor); the other is recorded as a sibling."""
    scan = _scan(tmp_path, {"p.py": _A_FIRST})
    v = _surfaces(scan, "p.py", "external_write")
    assert len(v) == 1, "the partition must collapse to a single display row (no exploded duplicates)"
    assert v[0].guard_proof.get("sibling_sink_lines"), "the folded sibling must be recorded in the trail"
    assert v[0].sink_line not in v[0].guard_proof["sibling_sink_lines"]


# ───────────────────────── 2. UNIT: the collapse invariant, all axes ─────────────────────────

class _FakeSurface:
    """Minimal stand-in carrying exactly the fields the shared band predicates + the collapse read."""
    def __init__(self, pid, line, *, verdict="EXPECTED_GUARD_MISSING", capability="external_write",
                 tainted_reachable=False, tainted_destination=False, dest_provenance="unknown",
                 context="prod", detection_source="static", display_pref=False):
        self.dedup_partition_id = pid
        self.dedup_display_pref = display_pref
        self.sink_line = line
        self.line_start = line
        self.verdict = verdict
        self.capability = capability
        self.tainted_reachable = tainted_reachable
        self.tainted_destination = tainted_destination
        self.dest_provenance = dest_provenance
        self.context = context
        self.detection_source = detection_source
        self.guard_proof = {}


# each case: (benign representative kwargs, band-driving sibling kwargs, expected survivor band rank)
_RED = dict(verdict="UNGUARDED_CRITICAL_LIVE_SINK", tainted_reachable=True)          # rank 4
_AMBER_FIXED = dict(verdict="CONFIG_DESTINATION_WRITE_REVIEW", tainted_reachable=True)  # rank 3
_AMBER_ACTION = dict(verdict="UNGUARDED_CRITICAL_LIVE_SINK", capability="post", tainted_reachable=True)  # rank 3
_INSTALL = dict(verdict="EXPECTED_GUARD_MISSING", capability="code_exec")            # rank 2 (RCE-class)
_BENIGN = dict(verdict="EXPECTED_GUARD_MISSING")                                      # rank 1


@pytest.mark.parametrize("axis,benign,dangerous,expect_rank", [
    # TAINT axis: untainted benign representative, tainted RED sibling.
    ("taint", dict(**_BENIGN, display_pref=True), _RED, 4),
    # DESTINATION axis: constant-dest AMBER representative, unknown-dest RED sibling.
    ("dest", dict(verdict="CONFIG_DESTINATION_WRITE_REVIEW", tainted_reachable=True,
                  dest_provenance="constant", display_pref=True), _RED, 4),
    # SHELL-FORM axis: non-shell AMBER representative, shell-injection RED sibling (subprocess_exec).
    ("shell", dict(verdict="SUBPROCESS_NON_SHELL_REVIEW", capability="subprocess_exec", display_pref=True),
     dict(verdict="UNGUARDED_CRITICAL_LIVE_SINK", capability="subprocess_exec", tainted_reachable=True), 4),
    # GUARD-STRENGTH axis (the reproduced hole): guarded/blue representative, decoy-guarded RED sibling.
    ("guard-strength", dict(verdict="NEEDS_RETEST", tainted_reachable=True, display_pref=True), _RED, 4),
    # CONTEXT/MUTATING axis (the 6th candidate): a dev (collector non-mutating) representative can't hide a
    # prod band-driving sibling — context is a band-predicate input, so worst-band picks the prod sink.
    ("context", dict(**dict(_RED, context="dev"), display_pref=True), _RED, 4),
    # RED vs AMBER-social: an install-liability representative can't hide a reachable amber action.
    ("amber-action", dict(**_INSTALL, display_pref=True), _AMBER_ACTION, 3),
    # RED vs fixed-dest AMBER: a benign representative can't hide a fixed-dest review sibling.
    ("amber-fixed", dict(**_BENIGN, display_pref=True), _AMBER_FIXED, 3),
])
def test_collapse_survivor_is_worst_band_over_all_members(axis, benign, dangerous, expect_rank):
    """The core structural invariant: after collapse, the single survivor's band rank == the MAX band rank
    over all raw members of the partition — on every axis. The display-preferred (benign) member can never
    win when a sibling drives a worse band."""
    rep = _FakeSurface("PID", 10, **benign)              # display-preferred benign representative, first
    sib = _FakeSurface("PID", 20, **dangerous)           # band-driving sibling, later
    members = [rep, sib]
    max_before = max(IR._surface_band_rank(m) for m in members)
    surfaces = list(members)
    diag = IR.collapse_dedup_to_worst_band(surfaces)
    # one row per partition — no over-count
    assert len(surfaces) == 1, f"[{axis}] partition must collapse to one row"
    survivor = surfaces[0]
    # survivor's band == worst raw band == the dangerous sibling's band (never the benign representative's)
    assert IR._surface_band_rank(survivor) == expect_rank == max_before, \
        f"[{axis}] survivor band {IR._surface_band_rank(survivor)} != worst {max_before}"
    assert survivor is sib, f"[{axis}] the benign representative hid the band-driving sibling"
    assert diag["band_promoted"] == 1, f"[{axis}] the promotion off the benign display row was not recorded"
    assert survivor.guard_proof["sibling_sink_lines"] == [10]


def test_collapse_all_benign_keeps_display_representative(tmp_path):
    """Anti-over-fire: when every member shares the worst band (all benign), the survivor is the
    display-preferred member (byte-identical display to before) and no promotion is recorded."""
    rep = _FakeSurface("PID", 3, **dict(_BENIGN, display_pref=True))
    sib = _FakeSurface("PID", 5, **_BENIGN)
    surfaces = [rep, sib]
    diag = IR.collapse_dedup_to_worst_band(surfaces)
    assert len(surfaces) == 1 and surfaces[0] is rep
    assert surfaces[0].sink_line == 3
    assert diag["band_promoted"] == 0
    assert surfaces[0].guard_proof["sibling_sink_lines"] == [5]


def test_collapse_ignores_non_partitioned_surfaces():
    """Surfaces with no dedup_partition_id (regex-fallback / AI-suspected) are never touched or folded."""
    a = _FakeSurface(None, 1)
    b = _FakeSurface(None, 2)
    surfaces = [a, b]
    diag = IR.collapse_dedup_to_worst_band(surfaces)
    assert surfaces == [a, b] and diag["partitions"] == 0 and diag["collapsed"] == 0
