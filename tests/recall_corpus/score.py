#!/usr/bin/env python3
"""Score a scan of the adversarial recall corpus against MANIFEST.json.

Reads:
  - MANIFEST.json (ground truth: planted reachable sinks + decoys)
  - a scan-output directory containing per-repo subdirs, each holding the
    scanner's outputs/hermes_action_surface_scan.json

Reusable for BOTH the static scanner and (later) the agentic finder — point it
at whichever scan-output tree you produced.

Usage:
    python3 score.py <scan_out_dir> [--manifest MANIFEST.json] [--tol N]

Layout expected under <scan_out_dir>:
    <scan_out_dir>/<repo>/outputs/hermes_action_surface_scan.json

Matching rule: a planted/decoy row is CAUGHT if the scan emitted an action
surface in the same repo + same file (by basename) whose SINK LINE (the actual
call site) is within --tol lines (default 3) of the manifest line. Capability
strings are NOT required to match (the scanner labels indirection generically);
locality of the *sink* is the signal that the danger was seen.

Anti-inflation discipline (Fable-5 recall audit): matching anchors on the true
sink line only, never on a surface's enclosing-function span (line_start /
line_end). Otherwise a distant planted row bleeds onto a NEIGHBOURING surface
via the span edge within ±tol (e.g. tools.py:20's cross-file `_ex=exec`, which
the engine does NOT resolve, was falsely credited to the raw_tool surface at
line 28 because that surface's line_start=23 sits 3 lines from 20). A single
surface is also credited to AT MOST ONE planted row (closest wins), so one
detected sink can never satisfy two distinct planted sinks. Together these keep
the recall number honest: it counts sinks the scanner actually located, not
locality coincidences.

Precision: a decoy is a FALSE POSITIVE only if a matching surface is reported as
an UNGUARDED live danger (verdict UNGUARDED_CRITICAL_LIVE_SINK, or any verdict
with NO guard attributed for a decoy whose whole point is that it's guarded or
benign). Guarded decoys where the scanner attributed a guard are correct, not FP.
"""
import argparse
import json
import os
import sys

UNGUARDED_VERDICTS = {
    "UNGUARDED_CRITICAL_LIVE_SINK",
    "BLOCK_LIVE_PROMOTION",
    "SUBPROCESS_SHELL_REVIEW",
}


def load_surfaces(scan_out_dir, repo):
    path = os.path.join(scan_out_dir, repo, "outputs",
                        "hermes_action_surface_scan.json")
    if not os.path.isfile(path):
        return None
    with open(path) as fh:
        data = json.load(fh)
    return data.get("surfaces", [])


def surface_lines(s):
    """The TRUE sink-line anchor(s) of a surface — the actual call site, NOT the
    enclosing-function span. Anchoring on the sink line (and the line embedded in
    the surface id `file.py:LINE:cap`) is what keeps recall honest: the span
    (line_start/line_end) is only used as a last-resort fallback when a surface
    carries no sink anchor at all, so a function span can never compete with a
    real sink line and bleed a distant planted row onto a neighbouring surface."""
    out = set()
    v = s.get("sink_line")
    if isinstance(v, int) and v > 0:
        out.add(v)
    # some surfaces carry the line inside the id: file.py:LINE:cap
    sid = s.get("id", "")
    parts = sid.split(":")
    if len(parts) >= 2 and parts[-2].isdigit():
        out.add(int(parts[-2]))
    # Fallback ONLY when the surface exposes no true sink anchor (defensive; the
    # scanner always emits sink_line today). The span never competes otherwise.
    if not out:
        for k in ("line_start", "line_end"):
            v = s.get(k)
            if isinstance(v, int) and v > 0:
                out.add(v)
    return out


def _candidate(row, s, tol):
    """Distance (<=tol) from a row's line to a surface's nearest sink anchor, or
    None if the surface is in a different file or out of tolerance."""
    if os.path.basename(s.get("file_path", "")) != os.path.basename(row["file"]):
        return None
    lines = surface_lines(s)
    if not lines:
        return None
    d = min(abs(ln - row["line"]) for ln in lines)
    return d if d <= tol else None


def match(row, surfaces, tol):
    """Return the single closest matching surface (or None) for a manifest row.
    Used for decoy precision (a decoy is scored independently)."""
    best = None
    for s in surfaces:
        d = _candidate(row, s, tol)
        if d is None:
            continue
        if best is None or d < best[0]:
            best = (d, s)
    return best[1] if best else None


def match_recall(rows, surfaces, tol):
    """One-to-one greedy assignment of planted rows to surfaces: each surface is
    credited to AT MOST ONE row (closest wins), so a single detected sink cannot
    satisfy two distinct planted sinks. Returns {row_index: surface} for matched
    rows. Ties (equal distance) break toward the lower planted line for stable,
    deterministic scoring."""
    cands = []  # (dist, row_index, surface_index)
    for ri, row in enumerate(rows):
        for si, s in enumerate(surfaces):
            d = _candidate(row, s, tol)
            if d is not None:
                cands.append((d, rows[ri]["line"], ri, si))
    cands.sort(key=lambda t: (t[0], t[1], t[2], t[3]))
    used_rows, used_surfaces, assigned = set(), set(), {}
    for d, _line, ri, si in cands:
        if ri in used_rows or si in used_surfaces:
            continue
        used_rows.add(ri)
        used_surfaces.add(si)
        assigned[ri] = surfaces[si]
    return assigned


def guard_attributed(s):
    g = s.get("guards", {}) or {}
    return any(v is True for k, v in g.items() if k != "markers") \
        or bool(g.get("markers"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scan_out_dir")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--manifest", default=os.path.join(here, "MANIFEST.json"))
    ap.add_argument("--tol", type=int, default=3)
    args = ap.parse_args()

    with open(args.manifest) as fh:
        manifest = json.load(fh)

    planted = manifest["planted"]
    decoys = manifest["decoys"]

    # cache surfaces per repo
    repos = sorted({r["repo"] for r in planted + decoys})
    surfaces_by_repo = {}
    missing_scans = []
    for repo in repos:
        surf = load_surfaces(args.scan_out_dir, repo)
        if surf is None:
            missing_scans.append(repo)
            surfaces_by_repo[repo] = []
        else:
            surfaces_by_repo[repo] = surf

    if missing_scans:
        print("WARNING: no scan output found for repos: %s"
              % ", ".join(missing_scans), file=sys.stderr)

    # RECALL over planted reachable sinks — assigned ONE-TO-ONE per repo so a
    # single detected surface can never be credited to two planted sinks.
    reachable = [r for r in planted if r.get("reachable")]
    caught, missed = [], []
    for repo in repos:
        rows = [r for r in reachable if r["repo"] == repo]
        if not rows:
            continue
        assigned = match_recall(rows, surfaces_by_repo[repo], args.tol)
        for ri, r in enumerate(rows):
            if ri in assigned:
                caught.append((r, assigned[ri]))
            else:
                missed.append(r)

    recall = 100.0 * len(caught) / len(reachable) if reachable else 0.0

    # PRECISION over decoys (false positives = decoy flagged as unguarded danger)
    false_positives = []
    for d in decoys:
        s = match(d, surfaces_by_repo[d["repo"]], args.tol)
        if s is None:
            continue  # not flagged at all -> correct
        # flagged: FP unless a guard was attributed
        if guard_attributed(s):
            continue  # guard recognised -> correct precision behaviour
        false_positives.append((d, s))

    n_dec = len(decoys)
    fp = len(false_positives)
    precision_note = "%d/%d decoys clean (%d false-positive%s)" % (
        n_dec - fp, n_dec, fp, "" if fp == 1 else "s")

    # ---- report ----
    print("=" * 72)
    print("ADVERSARIAL RECALL CORPUS — SCORE")
    print("scan dir : %s" % args.scan_out_dir)
    print("tol      : +/-%d lines" % args.tol)
    print("=" * 72)
    print("Planted reachable sinks : %d" % len(reachable))
    print("Caught                  : %d" % len(caught))
    print("Missed                  : %d" % len(missed))
    print("STATIC RECALL           : %.1f%%" % recall)
    print("-" * 72)
    print("Decoys                  : %d" % n_dec)
    print("PRECISION               : %s" % precision_note)
    print("=" * 72)
    print("MISS LIST (the gap the finder must close):")
    if not missed:
        print("  (none)")
    for r in sorted(missed, key=lambda x: (x["repo"], x["line"])):
        print("  - [%s] %s:%d  cap=%s  indirection=%s"
              % (r["repo"], r["file"], r["line"], r["capability"],
                 r["indirection_type"]))
    if false_positives:
        print("-" * 72)
        print("FALSE POSITIVES (decoys wrongly flagged as unguarded danger):")
        for d, s in false_positives:
            print("  - [%s] %s:%d  verdict=%s"
                  % (d["repo"], d["file"], d["line"], s.get("verdict")))
    print("=" * 72)

    # machine-readable summary for downstream automation
    summary = {
        "planted_reachable": len(reachable),
        "caught": len(caught),
        "missed": len(missed),
        "recall_pct": round(recall, 1),
        "decoys": n_dec,
        "false_positives": fp,
        "miss_list": [
            {"repo": r["repo"], "file": r["file"], "line": r["line"],
             "capability": r["capability"],
             "indirection_type": r["indirection_type"]}
            for r in missed
        ],
    }
    print(json.dumps(summary))
    return summary


if __name__ == "__main__":
    main()
