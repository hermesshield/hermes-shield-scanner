# =============================================================================
# CVE-2023-39662 — faithful exploit-usage harness (entrypoint driver ONLY)
# =============================================================================
# This file is NOT part of llama-index. It is a minimal, faithful reproduction
# of the *documented exploit usage* of the CVE: an application that wires
# attacker-controlled input straight into LlamaIndex's PandasQueryEngine eval
# path. It exists only to give the scanner a real ENTRYPOINT so it can trace
# taint from an untrusted ingress to the eval/exec sink inside the genuinely
# vulnerable, byte-for-byte upstream file at:
#     vuln_pkg/llama_index/query_engine/pandas_query_engine.py
#     (llama-index==0.7.13, MIT — see UPSTREAM_LICENSE_MIT.txt; unmodified,
#      sha256 == the wheel's RECORD entry, so the eval stays on line 58)
#
# The sink itself (exec line 53 / eval line 58 in default_output_processor) is
# the REAL upstream code — this harness adds no eval of its own. A library on
# its own has no entrypoint; this is how a real app reaches the flaw.
# CVE: https://nvd.nist.gov/vuln/detail/CVE-2023-39662  (CVSS 9.8, RCE)
# =============================================================================
import pandas as pd
from flask import Flask, request

from llama_index.query_engine.pandas_query_engine import default_output_processor

app = Flask(__name__)
_df = pd.DataFrame({"a": [1, 2, 3]})


@app.route("/ask")
def ask():
    # Attacker-controlled HTTP parameter — the untrusted ingress.
    user_query = request.args.get("q")
    # Flows straight into the REAL upstream eval/exec path -> arbitrary code exec.
    return default_output_processor(user_query, _df)
