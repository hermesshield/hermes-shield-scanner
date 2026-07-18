# Adversarial Recall Corpus

A small, hand-traced corpus for measuring how well a scanner finds **dangerous
action sinks reached from untrusted input** when the danger is hidden behind
real-world indirection (registry/factory dispatch, builtin aliasing, cross-file
wrappers, getattr dynamic dispatch, generic-verb libraries).

It exists to measure the gap between the **static scanner** (what ships today)
and the **agentic finder** (what we are building). The same `score.py` runs
against either scanner's output — point it at whichever scan-output tree you
produced.

## What is in it

- `repos/` — 8 tiny, self-contained "agent" codebases, each with a clearly
  labelled untrusted ingress and hand-traced flows to sinks.
- `MANIFEST.json` — ground truth. Every planted sink and decoy, with its exact
  call-site line, whether it is reachable from an untrusted ingress, the correct
  triage verdict (RED / BLUE / IGNORE), and the indirection used to hide it.
- `score.py` — matches a scan's reported surfaces against the manifest by
  file + line locality (±3 lines) and prints recall + precision.
- `scan_out_static/` — the static scanner's output, one subdir per repo.

### Size (current)

| | count |
|---|---|
| Planted reachable sinks (RED) | **21** |
| Decoys (must NOT be flagged as a live danger) | **9** |
| Repos | 8 |

Decoys break down as: 6 benign (no capability → IGNORE), 2 guarded (dry-run +
human-approval → BLUE), 1 reachable-but-sanitised (allowlisted upstream → BLUE).

## How to score

```
python3 score.py scan_out_static            # static scanner (baseline)
python3 score.py <finder_scan_out_dir>      # agentic finder (later)
```

## FINAL measured — static scanner (the baseline the finder must beat)

Measured with `score.py scan_out_static`, scanner v0.8.0.

| Corpus | Planted | Recall | Decoys | Precision |
|---|---|---|---|---|
| Original (numbers of record) | 20 | **50.0%** (10/20) | 7 | **7/7 clean** (0 FP) |
| **Extended (current)** | **21** | **47.6%** (10/21) | **9** | **8/9 clean** (1 FP) |

- Static catches the 10 literal / import-alias / immediate-getattr-call sinks
  and **never regresses** on them.
- The 11 static-missed sinks are the indirections the finder exists to close:
  builtin aliasing, getattr-assigned dynamic dispatch, generic-verb libraries,
  and the new aliased **exfil** sink.
- The single static false positive is the new **reachable-but-sanitised** decoy
  (`webhook_ops/sanitised.py:21`): static flags an allowlisted subprocess call
  as `UNGUARDED_CRITICAL_LIVE_SINK` because it does not track the upstream
  allowlist. This is a *deliberate, honest* FP — it is the false-positive
  discipline case the finder must de-escalate. The original 7 decoys remain
  0-FP under static.

## Hard cases added (from the Fable-5 corpus review)

The review confirmed all existing labels correct (no mislabels) and named three
missing hard cases, now added:

1. **Dedicated EXFIL** — `secret_exfil/` (S22): read a live env secret, then
   POST it to an attacker-controlled URL via an aliased `requests.post`. A
   cap-that-matters that the corpus previously only covered generically. Static
   misses it (aliased attribute-ref post).
2. **Dynamic-dispatch-to-BENIGN decoy** — `agent_tool_runner/tools.py:60`
   (D08): identical `getattr`-assigned shape to the RED dispatch sinks, but the
   receiver is a benign text-ops object. Stops the finder learning "any dynamic
   dispatch = danger". Static correctly ignores it (no FP).
3. **Reachable-but-sanitised decoy** — `webhook_ops/sanitised.py:21` (D09):
   untrusted input reaches a live subprocess sink but is neutralised by a strict
   allowlist first. Tests false-positive discipline on neutralised flows.

## Proposed bars — PENDING HARLEY SIGN-OFF

These are the bars proposed by the Fable-5 review, recorded verbatim. **Not yet
ratified.** They are written against the corpus as reviewed (20 planted / 7
decoys); see the editorial note below for the arithmetic against the extended
corpus.

```json
{
  "recall": "Overall floor 90% (>=18/20) with cap-weighted hard sub-bars. HARD: 100% on catastrophic caps (RCE = code_exec + subprocess_exec, and payment) = 13/13, no exceptions — 7 of the 10 static-missed sinks are RCE/payment (tools.py:20/28, compute.py:12, loader.py:19, shell_plugin.py:13, admin.py:34, gateways.py:25); missing even one reachable RCE or money-movement sink is indefensible for a security product. Comms caps (dm/telegram/email/webhook, 7 sinks): >=5/7 (the two generic-verb-on-unresolved-receiver cases, senders.py:18 telethon and channels.py:27 sendgrid, may need type inference the finder can't always do). Gap-closure: of the 10 static-missed sinks the finder must catch >=8 (80% of the gap it exists to close). Never regress on the 10 literal sinks static already catches (retain 100%).",
  "precision": "0 false positives on the corpus under a STRICT verdict reading: 0/5 benign IGNORE decoys flagged as a live danger (zero tolerance); both guarded BLUE decoys must attribute the guard AND not carry an unguarded-critical verdict (verdict not in {UNGUARDED_CRITICAL_LIVE_SINK, BLOCK_LIVE_PROMOTION, SUBPROCESS_SHELL_REVIEW}) — stricter than the current scorer, which the static scanner already fails on safe_ops.py:21. Max FP rate for ship = 0/7; any slack capped at <=1/7 (<=14%) and only on a guarded (never benign) decoy. Recommend tightening score.py so a decoy carrying an unguarded-critical verdict counts as an FP even when guard markers are present."
}
```

### Editorial note for sign-off (arithmetic against the extended corpus)

The corpus was extended per the same review (the three hard cases above), so
when ratifying, read the bars against **21 planted / 9 decoys**:

- **Recall floor 90% → ≥19/21.** The new exfil sink `secret_exfil/exfil.py:22`
  is an additional **catastrophic-cap** miss (exfil is a cap-that-matters); the
  finder must catch it. Gap-closure is now ≥8 of **11** static-missed sinks.
- **Precision.** There are now 6 benign IGNORE decoys and 3 BLUE decoys (2
  guarded + 1 sanitised). Zero tolerance on the 6 benign; the sanitised decoy
  (D09) is the neutralised-flow discipline case — a ship-quality finder should
  de-escalate it rather than carry an unguarded-critical verdict.

### Recommended scorer tightening (also from the review)

`score.py` currently forgives a decoy that carries an unguarded-critical verdict
as long as guard markers are attributed. This lets the static scanner's
self-contradictory verdict on `webhook_ops/safe_ops.py:21`
(`UNGUARDED_CRITICAL_LIVE_SINK` **with** dry-run + human-approval markers) pass.
The review recommends counting a decoy as a false positive when it carries any
verdict in `{UNGUARDED_CRITICAL_LIVE_SINK, BLOCK_LIVE_PROMOTION,
SUBPROCESS_SHELL_REVIEW}` even if guard markers are present. This is a
scorer/scanner tightening for the finder, not a corpus mislabel.
