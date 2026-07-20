"""
test_s8_86_install_liability_rating — locks the OWASP-on-the-inherited rating (ITEM 1 / S8.86).

The public dashboard (hermes_shield_site/app/public-scans) bands install-liability Low/Med/High by
RCE-class surface COUNT (Low <=16, Med 17-99, High >=100); the TOOL did not emit it. This test locks:
  - the aggregate band per the dashboard's own numbers (babyagi/notte/RA.Aid = Low ... cua = High),
  - the band boundaries (16 Low, 17 Med, 99 Med, 100 High),
  - the SOUND-LEANING guardrail: every per-surface inherited rating is capped at Med (never High),
  - build_report emits `install_liability_rating` and render() shows the inherited band.
"""
from __future__ import annotations
import sys
from pathlib import Path
from types import SimpleNamespace


from hermes_shield import install_report as IR  # noqa: E402


def _rce_surfaces(n):
    return [SimpleNamespace(capability="code_exec", language="python") for _ in range(n)]


# --- dashboard parity: the exact liab counts + published ratings (public-scans PublicScansDashboard) ---
def test_dashboard_band_parity():
    cases = {
        "cua": (261, "High"),
        "Langflow": (47, "Med"),
        "letta": (34, "Med"),
        "potpie": (34, "Med"),
        "llama_index": (26, "Med"),
        "SuperAGI": (22, "Med"),
        "julep": (21, "Med"),
        "agno": (20, "Med"),
        "RA.Aid": (16, "Low"),
        "semantic-kernel": (15, "Low"),
        "notte": (13, "Low"),
        "babyagi": (11, "Low"),
    }
    for name, (count, expect) in cases.items():
        r = IR.install_liability_rating(_rce_surfaces(count))
        assert r["band"] == expect, f"{name}: count={count} -> {r['band']}, expected {expect}"
        assert r["count"] == count


def test_band_boundaries():
    assert IR.install_liability_rating(_rce_surfaces(0))["band"] == "Low"
    assert IR.install_liability_rating(_rce_surfaces(16))["band"] == "Low"   # Low ceiling
    assert IR.install_liability_rating(_rce_surfaces(17))["band"] == "Med"   # Med floor
    assert IR.install_liability_rating(_rce_surfaces(99))["band"] == "Med"   # Med ceiling
    assert IR.install_liability_rating(_rce_surfaces(100))["band"] == "High"  # High floor


def test_per_surface_capped_at_med_sound_leaning():
    # SOUND-LEANING: no single inherited surface may be badged High off a static count, even in the High band.
    r = IR.install_liability_rating(_rce_surfaces(261))
    assert r["band"] == "High"
    assert r["per_surface"]["High"] == 0, "per-surface must never be High (inert here)"
    assert r["per_surface"]["Med"] == 261
    assert r["as_installed_likelihood"] == 2


def test_build_report_emits_rating():
    # a minimal scan with RCE-class install-liability surfaces (not grounded-critical -> inherited)
    surfaces = [SimpleNamespace(capability="code_exec", verdict="NEEDS_CALL_GRAPH", context="prod",
                                file_path=f"pkg/mod{i}.py", line_start=1, sink_line=0,
                                tainted_reachable=False, language="python") for i in range(20)]
    scan = {"surfaces": surfaces, "files_scanned": 20}
    rep = IR.build_report(Path("."), scan)
    assert "install_liability_rating" in rep
    assert rep["install_liability_rce"] == 20
    assert rep["install_liability_rating"]["band"] == "Med"     # 20 -> Med
    # headline (proven-live) unchanged — nothing PoC-confirmed
    assert rep["overall_rating"].startswith("None")
    # render carries the inherited band verbatim
    md = IR.render(rep)
    assert "inherited rating: Med" in md
    assert "aggregate-count signal" in md


# --- NIT 4: never print an "inherited rating" on an EMPTY install-liability set ---------------------
def test_render_omits_inherited_rating_when_no_install_liability():
    # a clean scan with ZERO install-liability surfaces must NOT show "inherited rating: Low" — a rating
    # on an empty set reads as a residual-risk score on nothing.
    scan = {"surfaces": [], "files_scanned": 3}
    rep = IR.build_report(Path("."), scan)
    assert rep["install_liability_rce"] == 0
    md = IR.render(rep)
    assert "INSTALL-LIABILITY (RCE-class): 0" in md      # the count line still renders
    assert "inherited rating" not in md                  # ...but the rating label does NOT
    assert "Inherited rating:" not in md                 # ...nor the detail bullet
    # the rating STILL rides when there IS something to rate (guards against over-suppression)
    liab = [SimpleNamespace(capability="code_exec", verdict="NEEDS_CALL_GRAPH", context="prod",
                            file_path=f"pkg/m{i}.py", line_start=1, sink_line=0, tainted_reachable=False,
                            language="python") for i in range(3)]
    md2 = IR.render(IR.build_report(Path("."), {"surfaces": liab, "files_scanned": 3}))
    assert "inherited rating:" in md2


# --- NIT 1: REACHABILITY_UNKNOWN rows are de-duped by stable identity (file, line, capability) -------
def test_reachability_unknown_deduped_by_stable_identity():
    # TWO surfaces that are the SAME physical sink (same file+line+capability), reached from two callers.
    # An untrusted ingress makes them reachability-unknown. They must collapse to ONE row + ONE count.
    def _sink():
        return SimpleNamespace(capability="code_exec", verdict="NEEDS_CALL_GRAPH", context="prod",
                               detection_source="static", file_path="agent/modal_sandbox_v2.py",
                               line_start=166, sink_line=166, tainted_reachable=False, language="python")
    scan = {"surfaces": [_sink(), _sink()], "files_scanned": 5,
            "ingresses": [SimpleNamespace(id="i1")]}   # untrusted ingress -> reachability-unknown, not inert
    rep = IR.build_report(Path("."), scan)
    assert rep["reachability_unknown"] == 1, "the same sink at one line must count once, not twice"
    items = rep["reachability_unknown_items"]
    assert len(items) == 1
    assert items[0]["file"].endswith("modal_sandbox_v2.py") and items[0]["line"] == 166
    # genuinely-distinct sinks (different line) are NOT collapsed
    s2 = SimpleNamespace(capability="code_exec", verdict="NEEDS_CALL_GRAPH", context="prod",
                         detection_source="static", file_path="agent/modal_sandbox_v2.py",
                         line_start=200, sink_line=200, tainted_reachable=False, language="python")
    rep2 = IR.build_report(Path("."), {"surfaces": [_sink(), _sink(), s2], "files_scanned": 5,
                                       "ingresses": [SimpleNamespace(id="i1")]})
    assert rep2["reachability_unknown"] == 2
