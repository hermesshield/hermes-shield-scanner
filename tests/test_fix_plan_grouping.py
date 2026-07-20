"""
test_fix_plan_grouping — DE-NOISE the fix plan.

The machine feed (hermes_patch_plan.json) is COMPLETE: one row per dangerous call site (the Repairer needs
every one). But a human drowns in it — a real repo yields hundreds of rows that all close under a HANDFUL of
real fixes (one tool-dispatcher gate covers every tool_invoke call site; one CSRF/Origin middleware covers
every dashboard_mutation endpoint). These tests lock the de-noise contract:

  1. GROUPING ONLY — the inventory count is never changed; sum(group counts) == len(inventory); no genuine
     distinct fix (capability/control point) is ever merged away or dropped.
  2. SMALL card count — the human report renders ~12-15 cards for a large repo, not hundreds.
  3. FIX THESE FIRST — the top-5 are the highest-LEVERAGE (sites-closed × severity) actionable groups.
  4. RECLASSIFICATION — a read-only surface is INFORMATIONAL ("no gate needed"), never a critical fix, and
     never eligible for the top-5.
"""
from __future__ import annotations
from types import SimpleNamespace

from hermes_shield import patch_plan as PP


def _item(cap, verdict, file="pkg/x.py", line=10, block=False):
    """A minimal PatchPlanItem-shaped object carrying the fields group_plan reads."""
    gid, cp = PP.control_point(cap)
    return SimpleNamespace(
        capability=cap, verdict=verdict, fix_group_id=gid, control_point=cp,
        fix_class=PP.actionability(verdict), suggested_file=file, block_live_promotion=block,
        finding=f"{cap} at {file}:{line} verdict={verdict}", severity="critical")


# A synthetic inventory shaped like a real large-repo scan (letta): one dominant dispatcher group + a CSRF
# group + a fixed-destination review band + a read-only informational band + a couple of hard RCE sinks.
def _big_inventory():
    items = []
    items += [_item("tool_invoke", "BLOCK_LIVE_PROMOTION", file=f"a/t{i}.py", line=i, block=True)
              for i in range(380)]                                    # one dispatcher gate
    items += [_item("dashboard_mutation", "NEEDS_CERTIFICATION", file=f"b/d{i}.py", line=i)
              for i in range(100)]                                    # one CSRF middleware (review)
    items += [_item("external_write", "CONFIG_DESTINATION_WRITE_REVIEW", file=f"c/w{i}.py", line=i)
              for i in range(150)]                                    # fixed-dest provider writes (review)
    items += [_item("model_call", "READ_ONLY_SURFACE", file=f"d/m{i}.py", line=i)
              for i in range(30)]                                     # read-only -> informational
    items += [_item("code_exec", "UNGUARDED_CRITICAL_LIVE_SINK", file=f"e/c{i}.py", line=i, block=True)
              for i in range(12)]                                     # hard RCE (gate, sev 5)
    items += [_item("subprocess_exec", "SUBPROCESS_NON_SHELL_REVIEW", file=f"f/s{i}.py", line=i)
              for i in range(20)]                                     # subprocess review (sev 5)
    return items


# ---- 1. GROUPING ONLY — inventory count preserved, nothing dropped or merged ----

def test_grouping_preserves_the_full_inventory_count():
    inv = _big_inventory()
    groups = PP.group_plan(inv)
    # every single inventory row is accounted for in exactly one group — no row dropped, none duplicated
    assert sum(g["count"] for g in groups) == len(inv)


def test_two_distinct_capabilities_are_never_merged():
    # code_exec and subprocess_exec are DISTINCT fixes — grouping must never collapse them into one card
    groups = PP.group_plan([_item("code_exec", "UNGUARDED_CRITICAL_LIVE_SINK"),
                            _item("subprocess_exec", "UNGUARDED_CRITICAL_LIVE_SINK")])
    caps = {g["capability"] for g in groups}
    assert caps == {"code_exec", "subprocess_exec"}
    assert len({g["fix_group_id"] for g in groups}) == 2   # distinct control points -> distinct groups


# ---- 2. SMALL card count for a large repo ----

def test_card_count_is_small_for_a_large_inventory():
    inv = _big_inventory()                    # 692 rows
    groups = PP.group_plan(inv)
    assert len(inv) > 200                      # the inventory really is large (would drown a human)
    assert len(groups) <= 15                   # ...but the human sees a small handful of cards
    # and a MASSIVE de-noise ratio: hundreds of rows -> a dozen cards
    assert len(groups) < len(inv) / 10


def test_one_gate_reports_the_many_sites_it_closes():
    inv = _big_inventory()
    groups = PP.group_plan(inv)
    disp = next(g for g in groups if g["fix_group_id"] == "tool-dispatcher-gate")
    assert disp["count"] == 380                # "this one gate covers 380 call sites"
    assert len(disp["locations"]) == 380       # every site is retained on the group for the JSON roll-up


# ---- 3. FIX THESE FIRST — top-5 are the highest-leverage actionable groups ----

def test_top5_are_the_highest_leverage_groups():
    inv = _big_inventory()
    groups = PP.group_plan(inv)
    top5 = PP.top_fixes(groups, 5)
    assert len(top5) == 5
    # leverage = sites-closed × severity; the returned five ARE the five highest-leverage actionable groups
    actionable = sorted((g for g in groups if g["leverage"] > 0),
                        key=lambda g: -g["leverage"])
    assert [g["fix_group_id"] for g in top5] == [g["fix_group_id"] for g in actionable[:5]]
    # monotonically non-increasing leverage
    levs = [g["leverage"] for g in top5]
    assert levs == sorted(levs, reverse=True)
    # the dispatcher (380 sites) is the single highest-leverage fix
    assert top5[0]["fix_group_id"] == "tool-dispatcher-gate"
    assert top5[0]["leverage"] == 380 * PP._SEVERITY["tool_invoke"]


# ---- 4. RECLASSIFICATION — read-only is informational, never a fix, never top-5 ----

def test_read_only_surface_is_informational_not_critical():
    groups = PP.group_plan([_item("model_call", "READ_ONLY_SURFACE")])
    g = groups[0]
    assert g["fix_class"] == "informational"
    assert g["leverage"] == 0                              # never counts as leverage
    assert "no gate needed" in g["control"].lower()       # honest reclassification, not a fix instruction


def test_informational_group_never_appears_in_top5():
    inv = _big_inventory()
    groups = PP.group_plan(inv)
    top5 = PP.top_fixes(groups, 5)
    assert all(g["fix_class"] != "informational" for g in top5)
    assert all(g["fix_class"] in ("gate", "review") for g in top5)


def test_actionability_classes():
    assert PP.actionability("READ_ONLY_SURFACE") == "informational"
    assert PP.actionability("CONFIG_DESTINATION_WRITE_REVIEW") == "review"
    assert PP.actionability("NEEDS_CERTIFICATION") == "review"
    assert PP.actionability("NEEDS_CALL_GRAPH") == "held"
    assert PP.actionability("BLOCK_LIVE_PROMOTION") == "gate"
    assert PP.actionability("UNGUARDED_CRITICAL_LIVE_SINK") == "gate"


# ---- 5. build() stamps the grouping fields onto every inventory row (JSON feed carries them) ----

def test_build_stamps_control_point_and_fix_group_id():
    def _surf(cap, verdict="UNGUARDED_CRITICAL_LIVE_SINK"):
        return SimpleNamespace(
            id="s1", capability=cap, verdict=verdict, context="prod", detection_source="static",
            file_path="pkg/x.py", line_start=10, risk_level="HIGH", live_capable=True,
            guards=SimpleNamespace(kill_switch=False), tainted_reachable=True, language="python")
    items = PP.build([_surf("tool_invoke"), _surf("dashboard_mutation", "NEEDS_CERTIFICATION"),
                      _surf("model_call", "READ_ONLY_SURFACE")])
    by_cap = {it.capability: it for it in items}
    assert by_cap["tool_invoke"].fix_group_id == "tool-dispatcher-gate"
    assert by_cap["dashboard_mutation"].fix_group_id == "dashboard-csrf-origin"
    assert by_cap["tool_invoke"].control_point and by_cap["tool_invoke"].fix_class == "gate"
    assert by_cap["dashboard_mutation"].fix_class == "review"
    assert by_cap["model_call"].fix_class == "informational"
    # to_dict carries the new fields into hermes_patch_plan.json
    assert "fix_group_id" in items[0].to_dict() and "control_point" in items[0].to_dict()


# ---- 6. the real letta-shaped inventory de-noises 746 rows -> ~12 cards, count preserved ----

def test_group_plan_accepts_legacy_dict_rows_and_preserves_count():
    # rows WITHOUT the new fields (legacy hermes_patch_plan.json) must still group by recovering the
    # capability/verdict from the finding string — and still preserve the inventory count.
    legacy = [{"finding": "tool_invoke at a/t.py:1 verdict=BLOCK_LIVE_PROMOTION", "suggested_file": "a/t.py",
               "block_live_promotion": True} for _ in range(50)]
    legacy += [{"finding": "model_call at d/m.py:2 verdict=READ_ONLY_SURFACE", "suggested_file": "d/m.py",
                "block_live_promotion": False} for _ in range(10)]
    groups = PP.group_plan(legacy)
    assert sum(g["count"] for g in groups) == 60
    # tool_invoke -> its mapped control point; model_call is unmapped -> its OWN per-capability fallback slug
    # (never a shared bucket, so two distinct unmapped capabilities can never collapse into one card)
    assert {g["fix_group_id"] for g in groups} == {"tool-dispatcher-gate", "model-call-generic-control-gate"}
    info = next(g for g in groups if g["capability"] == "model_call")
    assert info["fix_class"] == "informational"


def test_distinct_unmapped_capabilities_get_distinct_fallback_groups():
    # model_call and external_read are BOTH read-only/unmapped — but distinct capabilities, so distinct cards
    groups = PP.group_plan([_item("model_call", "READ_ONLY_SURFACE"),
                            _item("external_read", "READ_ONLY_SURFACE")])
    assert len({g["fix_group_id"] for g in groups}) == 2
    assert {g["capability"] for g in groups} == {"model_call", "external_read"}
