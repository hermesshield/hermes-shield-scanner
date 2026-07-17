"""
audit finding #2 (HIGH with --ai; MED core, CWE-61/CWE-22) — repository traversal must not follow
symlinked source files or directories that resolve OUTSIDE the canonical target root. A malicious repo
must not be able to make the scanner read arbitrary local files by packaging them as symlinked `*.py`.
"""
import tempfile
from pathlib import Path

from hermes_shield import repo_scanner


def test_scan_skips_symlinked_py_files():
    d = Path(tempfile.mkdtemp())
    outside = Path(tempfile.mkdtemp()) / "secret.py"
    outside.write_text("SECRET = 'do-not-read'\n")
    (d / "real.py").write_text("print(1)\n")
    (d / "leak.py").symlink_to(outside)   # symlinked file resolving outside root

    files = {str(p.relative_to(d)) for p in repo_scanner._iter_py(d)}
    assert "real.py" in files, "a genuine in-root file must still be scanned"
    assert "leak.py" not in files, "a symlinked out-of-root .py must be skipped"

    # defence in depth: a symlinked DIRECTORY pointing outside root must also be skipped
    outside_dir = Path(tempfile.mkdtemp())
    (outside_dir / "ext.py").write_text("X = 1\n")
    (d / "linkdir").symlink_to(outside_dir, target_is_directory=True)
    all_files = {str(p) for p in repo_scanner._iter_py(d)}
    assert not any(p.endswith("ext.py") for p in all_files), "files under a symlinked dir must be skipped"
