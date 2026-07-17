"""Baseline snapshot + load. Safe hashes only; no secrets."""
from __future__ import annotations
import json
from pathlib import Path
from .models import SCANNER_VERSION


def build_baseline(scan: dict, head: str) -> dict:
    return {
        "scanner_version": SCANNER_VERSION,
        "repo_head": head,
        "files_scanned": scan["files_scanned"],
        # P2.9B: keyed on STABLE identity (file, symbol, capability, sink), not line number
        "surfaces": {(s.stable_id or s.id): {"cap": s.capability, "risk": s.risk_level, "ctx": s.context,
                            "live": s.live_capable, "verdict": s.verdict, "scope": s.scope,
                            "fingerprint": s.fingerprint, "line": s.line_start,
                            "guard_evidence_level": s.guard_evidence_level, "sink": s.sink_name,
                            "guards": [k for k, v in s.guards.__dict__.items() if v is True]}
                     for s in scan["surfaces"]},
        "ingresses": {i.id: {"src": i.source_type, "fenced": i.fenced,
                             "classification": i.classification, "ctx": i.context}
                      for i in scan["ingresses"]},
    }


def save_baseline(baseline: dict, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")


def load_baseline(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
