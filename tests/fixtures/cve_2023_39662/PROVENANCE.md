# CVE-2023-39662 fixture — provenance

This fixture backs the README headline claim that the scanner catches a real
CVSS 9.8 RCE — **CVE-2023-39662** in llama-index's `PandasQueryEngine`.

## What the vulnerable code is (REAL upstream file, not a reproduction)

`vuln_pkg/llama_index/query_engine/pandas_query_engine.py` is the **genuine,
unmodified** source file from the vulnerable release:

- Package: `llama-index==0.7.13` (the documented vulnerable version; patched upstream since)
- Obtained via: `pip download llama-index==0.7.13 --no-deps` → wheel extracted
- Licence: MIT (see `UPSTREAM_LICENSE_MIT.txt`; copyright Jerry Liu / LlamaIndex)
- Integrity: byte-for-byte identical to the wheel. The wheel's `RECORD` lists
  `sha256=GE4jAtY69Uynh_Qu09-SMIsw92z8DKnP6lKuGZI2oC4` for this path; the
  vendored copy reproduces that exact digest. It is **not** edited — so the
  documented sink stays on its original line numbers:
    - **line 58 — `eval(...)`** (the documented CVE eval-on-LLM-output sink)
    - line 53 — `exec(...)` (the companion sink in the same function)

Both live in `default_output_processor`, which `PandasQueryEngine._query`
invokes on the LLM's response to an attacker-influenceable query.

## What `app.py` is (harness, NOT part of the CVE)

`app.py` is a small, faithful reproduction of the **documented exploit usage** —
a web handler that passes an untrusted HTTP parameter into the real eval path.
It adds no `eval`/`exec` of its own. Its only job is to provide a real
ENTRYPOINT so the scanner's entrypoint-grounded taint tracing can prove the
sink is reachable from untrusted input (a bare library has no entrypoint).

## Classification used here

- **Real package file** for the vulnerable code (the sink).
- **Faithful reproduction** for the exploit harness (the entrypoint only).

The regression test `tests/test_cve_2023_39662.py` scans this directory and
locks the result so the headline claim can never silently regress.
