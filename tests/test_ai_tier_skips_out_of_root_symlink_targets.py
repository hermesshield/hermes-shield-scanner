"""
audit finding #2 (HIGH with --ai) — the AI tier re-reads candidate files and forwards their CONTENT to
the local `claude` CLI. Its target selection must never include a symlinked file that resolves outside the
canonical target root, or those out-of-root contents would be disclosed to the AI tool.
"""
import tempfile
from pathlib import Path

from hermes_shield import ai_tier


def test_ai_tier_skips_out_of_root_symlink_targets():
    d = Path(tempfile.mkdtemp())
    outside = Path(tempfile.mkdtemp()) / "linked.py"
    # content that trips the AI risk/plumbing prefilter, so it WOULD be selected if not for containment
    outside.write_text("import subprocess\nsubprocess.Popen(cmd, shell=True)\n")
    (d / "link.py").symlink_to(outside)

    targets = ai_tier._target_files(d, [], 10)
    rels = [r for r, _ in targets]
    assert not any(r == "link.py" for r in rels), "AI tier selected a symlinked out-of-root file"
    assert targets == [], "no in-root candidate exists, so selection must be empty"
