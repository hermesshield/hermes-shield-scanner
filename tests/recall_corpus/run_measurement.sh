#!/bin/bash
# Combined static + AI-finder recall measurement over the adversarial corpus.
# Runs the SHIPPED CLI with --ai-deep (finder default = sonnet; Fable refuses this role).
# Each --ai-deep scan output already includes the static surfaces, so the resulting
# tree is the true combined static+finder output; score.py counts all surfaces.
set -u
cd /home/hartley/hermes-shield-scanner || exit 1
OUT=tests/recall_corpus/scan_out_aideep
BIN=.venv/bin/hermes-shield
REPOS="agent_tool_runner cli_admin dm_bot notification_hub payments_gateway plugin_loader secret_exfil webhook_ops"

rm -rf "$OUT"; mkdir -p "$OUT"
echo "=== AI-finder measurement (model=sonnet) started ==="
for r in $REPOS; do
  echo ">>> $r"
  HERMES_SHIELD_FINDER_MODEL=sonnet timeout 600 "$BIN" scan "tests/recall_corpus/repos/$r" \
      --ai-deep --out "$OUT/$r" --quiet 2>&1 | tail -3
  # per-repo evidence the finder actually ran (now serialised by the fail-loud fix)
  .venv/bin/python - "$OUT/$r" <<'PY'
import json, sys, glob
for f in glob.glob(sys.argv[1] + "/outputs/hermes_action_surface_scan.json"):
    d = json.load(open(f))
    af = d.get("ai_finder") or {}
    ai = [s for s in d.get("surfaces", []) if s.get("detection_source", "static") != "static"]
    print("    finder:", af.get("status"), "model=%s" % af.get("ai_finder_model") if af else "(no block)",
          "| ai_suspected surfaces:", len(ai))
PY
done

echo ""
echo "=== COMBINED static+finder SCORE ==="
.venv/bin/python tests/recall_corpus/score.py "$OUT"
echo ""
echo "=== ai_suspected surfaces landing on DECOY files (advisory precision — score.py does not penalise these) ==="
.venv/bin/python - "$OUT" <<'PY'
import json, glob, os, sys
out = sys.argv[1]
decoy_hits = 0
for f in glob.glob(os.path.join(out, "*", "outputs", "hermes_action_surface_scan.json")):
    repo = f.split("/")[-3]
    d = json.load(open(f))
    for s in d.get("surfaces", []):
        if s.get("detection_source", "static") != "static":
            print("   AI flag:", repo, s.get("file_path"), s.get("sink_line"), s.get("capability"))
print("(inspect against MANIFEST.json decoys to judge fabrication)")
PY
echo "=== measurement complete ==="
