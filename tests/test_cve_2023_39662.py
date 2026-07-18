"""
CI-LOCKED regression test for the README headline claim:

    "Catches a real CVSS 9.8 CVE at the documented line" —
    CVE-2023-39662, the remote-code-execution flaw in LlamaIndex's
    `PandasQueryEngine` (attacker-influenceable query -> eval/exec).

Before this test the claim had NO in-repo evidence: no fixture, no scan, no
assertion. This locks it so the claim can never silently regress.

WHAT IS SCANNED (see tests/fixtures/cve_2023_39662/PROVENANCE.md):
  * The vulnerable code is the REAL, byte-for-byte upstream file from
    `llama-index==0.7.13` (MIT) — unmodified, so the documented sink stays on
    its original lines: eval on line 58, exec on line 53, both inside
    `default_output_processor`. Verified byte-identical to the wheel RECORD.
  * `app.py` is a small, faithful reproduction of the DOCUMENTED EXPLOIT USAGE
    (an HTTP handler wiring an untrusted query into the real eval path). It is
    an ENTRYPOINT harness only and adds no eval/exec of its own — a bare library
    has no entrypoint, so this is how a real app reaches the flaw.

The assertions below confirm the scanner:
  (1) detects the `code_exec` sink at the exact documented eval line (58);
  (2) traces it reachable from the untrusted ingress and stamps the deterministic
      RED verdict UNGUARDED_CRITICAL_LIVE_SINK (static, prod);
  (3) bands it RED via the report's own non-gated-vulnerable partition.

If the scanner ever stops flagging this, the build fails here instead of the
README quietly becoming a false claim.
"""
from pathlib import Path

from hermes_shield import scan_hermes
from hermes_shield import install_report as IR

_FIXTURE = Path(__file__).parent / "fixtures" / "cve_2023_39662"
_VULN_FILE = "pandas_query_engine.py"
_CVE_EVAL_LINE = 58   # documented eval-on-LLM-output sink (upstream line, unmodified)
_CVE_EXEC_LINE = 53   # companion exec sink in the same function


def _scan():
    scan = scan_hermes.run_scan(_FIXTURE)
    return scan["surfaces"]


def _pandas_code_exec(surfaces):
    return [
        s for s in surfaces
        if _VULN_FILE in getattr(s, "file_path", "")
        and getattr(s, "capability", "") == "code_exec"
    ]


def test_fixture_is_the_real_unmodified_upstream_file():
    """The vulnerable code must be the genuine 0.7.13 file (byte-for-byte the wheel
    RECORD digest), so 'at the documented line' is a real claim, not a repro."""
    import base64
    import hashlib

    path = _FIXTURE / "vuln_pkg" / "llama_index" / "query_engine" / _VULN_FILE
    data = path.read_bytes()
    b64 = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    # sha256 recorded in the llama-index==0.7.13 wheel's RECORD for this path
    assert b64 == "GE4jAtY69Uynh_Qu09-SMIsw92z8DKnP6lKuGZI2oC4", (
        "vendored pandas_query_engine.py no longer matches the llama-index 0.7.13 "
        "wheel — the CVE line numbers / 'real package file' claim can no longer be trusted"
    )
    # And the documented sink is literally on the expected lines.
    lines = data.decode().splitlines()
    assert "eval(" in lines[_CVE_EVAL_LINE - 1], f"eval no longer on line {_CVE_EVAL_LINE}"
    assert "exec(" in lines[_CVE_EXEC_LINE - 1], f"exec no longer on line {_CVE_EXEC_LINE}"


def test_scanner_flags_cve_2023_39662_at_the_documented_eval_line():
    """(1)+(2): the code_exec RCE sink is detected at the documented eval line (58)
    and stamped the deterministic reachable-RED verdict UNGUARDED_CRITICAL_LIVE_SINK."""
    hits = _pandas_code_exec(_scan())
    by_line = {s.sink_line: s for s in hits}

    assert _CVE_EVAL_LINE in by_line, (
        f"scanner did not flag the code_exec sink at pandas_query_engine.py:"
        f"{_CVE_EVAL_LINE} — the headline CVE-2023-39662 claim is UNBACKED"
    )
    sink = by_line[_CVE_EVAL_LINE]
    assert sink.verdict == "UNGUARDED_CRITICAL_LIVE_SINK", (
        f"documented eval sink present but verdict={sink.verdict!r}, "
        f"expected UNGUARDED_CRITICAL_LIVE_SINK (reachable RED)"
    )
    assert sink.tainted_reachable is True, "eval sink must be reachable from the untrusted ingress"
    assert sink.detection_source == "static", "must be a deterministic (static) detection, not AI-suspected"
    assert sink.context == "prod", "must be a production surface"
    assert sink.symbol == "default_output_processor"


def test_scanner_also_flags_the_companion_exec_sink():
    """The exec sink (line 53) in the same function is likewise caught reachable-RED."""
    hits = _pandas_code_exec(_scan())
    by_line = {s.sink_line: s for s in hits}
    assert _CVE_EXEC_LINE in by_line, f"exec sink at line {_CVE_EXEC_LINE} not detected"
    assert by_line[_CVE_EXEC_LINE].verdict == "UNGUARDED_CRITICAL_LIVE_SINK"
    assert by_line[_CVE_EXEC_LINE].tainted_reachable is True


def test_cve_sink_is_banded_red_by_the_report():
    """(3): the report's own RED partition (static non-gated vulnerable) contains the
    CVE sink — this is the exact set the customer report/live verdict paints RED."""
    surfaces = _scan()
    red = [
        s for s in surfaces
        if getattr(s, "verdict", "") == "UNGUARDED_CRITICAL_LIVE_SINK"
        and getattr(s, "detection_source", "") == "static"
        and getattr(s, "context", "") == "prod"
        and IR.is_non_gated_vulnerable(s)
    ]
    red_pandas = [s for s in red if _VULN_FILE in getattr(s, "file_path", "")]
    assert red_pandas, "CVE-2023-39662 sink is not in the report's RED (non-gated vulnerable) partition"
    assert _CVE_EVAL_LINE in {s.sink_line for s in red_pandas}, "documented eval line not banded RED"
