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
surface in the same repo + same file (by basename) whose sink line is within
--tol lines (default 3) of the manifest line. Capability strings are NOT
required to match (the scanner labels indirection generically); locality is the
signal that the danger was seen.

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
    """All plausible line anchors the scanner attached to a surface."""
    out = set()
    for k in ("sink_line", "line_start", "line_end"):
        v = s.get(k)
        if isinstance(v, int) and v > 0:
            out.add(v)
    # some surfaces carry the line inside the id: file.py:LINE:cap
    sid = s.get("id", "")
    parts = sid.split(":")
    if len(parts) >= 2 and parts[-2].isdigit():
        out.add(int(parts[-2]))
    return out


def match(row, surfaces, tol):
    """Return the matching surface (or None) for a manifest row."""
    want_file = os.path.basename(row["file"])
    best = None
    for s in surfaces:
        if os.path.basename(s.get("file_path", "")) != want_file:
            continue
        lines = surface_lines(s)
        if not lines:
            continue
        if any(abs(ln - row["line"]) <= tol for ln in lines):
            # prefer the closest
            d = min(abs(ln - row["line"]) for ln in lines)
            if best is None or d < best[0]:
                best = (d, s)
    return best[1] if best else None


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

    # RECALL over planted reachable sinks
    reachable = [r for r in planted if r.get("reachable")]
    caught, missed = [], []
    for r in reachable:
        s = match(r, surfaces_by_repo[r["repo"]], args.tol)
        if s is not None:
            caught.append((r, s))
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
