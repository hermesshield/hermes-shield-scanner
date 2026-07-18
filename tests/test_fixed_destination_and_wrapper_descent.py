"""Fix1 (fixed-channel destination-awareness) + Fix2 (one-hop downward guard credit) regressions.

The whole point is to REMOVE the false alarms WITHOUT introducing under-reporting:
  * a fixed-channel messaging send with only tainted CONTENT (config destination) -> AMBER review, not RED;
  * a send to a TAINTED (attacker-controlled) destination -> STILL RED (never blanket-silenced);
  * a guarded WRAPPER call-site (a kill-switch dominates the callee's inner sink) -> credited, not RED;
  * an UNGUARDED wrapper (its callee has no dominating guard) -> STILL RED (callee-resolved, never name-based);
  * a truly unguarded reachable send -> STILL RED.
"""
from pathlib import Path

from hermes_shield import scan_hermes
from hermes_shield import install_report as IR
from hermes_shield import dashboard_export, patch_plan


def _scan(tmp_path, files):
    for name, src in files.items():
        (tmp_path / name).write_text(src)
    return scan_hermes.run_scan(tmp_path)


def _surfaces(scan, fname, cap):
    return [s for s in scan["surfaces"] if s.file_path == fname and s.capability == cap]


def _at(scan, fname, cap, line):
    return [s for s in _surfaces(scan, fname, cap) if s.sink_line == line]


def _band(tmp_path, scan):
    """The customer-facing RED / AMBER / BLUE band for a scanned repo — the SAME canonical path the HTML
    report and the CLI finale use (build_report -> verdict_band). Asserting on THIS (not the intermediate
    verdict string) is what actually proves the invariant 'nothing reachable-unguarded returns to BLUE'."""
    rep = IR.build_report(tmp_path, scan)
    vb = IR.verdict_band(rep["non_gated_vulnerable"], rep["proven_live_poc"],
                         rep["install_liability_rce"], rep["reachable_amber_actions"],
                         rep["reachable_fixed_dest_review"])
    return rep, vb


# ─────────────────────────── Fix 1: telegram destination-awareness ───────────────────────────

def test_telegram_config_destination_tainted_content_is_amber_not_red(tmp_path):
    """The 7-FP class: a telegram ops-notification whose CONTENT is tainted but whose chat_id is an
    operator config value (resolved through the local payload dict) is AMBER review, NEVER the RED
    UNGUARDED_CRITICAL_LIVE_SINK."""
    scan = _scan(tmp_path, {"tg.py":
        "import os, requests\n"
        "def send_alert(text):\n"                       # 'text' is untrusted content
        "    chat = os.getenv('TELEGRAM_CHAT_ID')\n"
        "    payload = {'chat_id': chat, 'text': text}\n"
        "    requests.post('https://api.telegram.org/bot123/sendMessage', json=payload)\n"})
    v = _surfaces(scan, "tg.py", "telegram_send")
    assert v, "telegram_send sink not detected"
    assert all(s.tainted_reachable for s in v)                 # content IS tainted
    assert all(not s.tainted_destination for s in v)           # but the destination is not
    assert all(s.verdict == "CONFIG_DESTINATION_WRITE_REVIEW" for s in v)
    assert all(s.verdict != "UNGUARDED_CRITICAL_LIVE_SINK" for s in v)
    # INVARIANT 3: the demotion must land in the AMBER band, NEVER blue. Asserting the customer-facing band
    # (not just the intermediate verdict string) is what proves "reachable-unguarded never returns to BLUE".
    rep, vb = _band(tmp_path, scan)
    assert rep["reachable_fixed_dest_review"] == len(v)
    assert rep["non_gated_vulnerable"] == 0                     # not red
    assert vb["code"] == "amber", "fixed-dest demotion must be AMBER review, never BLUE"


def test_telegram_param_destination_stays_red(tmp_path):
    """GAP-1 regression (the untested hole): a reachable telegram send whose chat_id arrives as an ordinary
    PARAMETER is NOT proof of a fixed operator channel — the taint bit is intra-function and cannot see the
    caller, so the attacker who controls that chat_id is a genuine exfil channel. Its destination provenance
    is UNKNOWN (not proven config/constant), so it gets NO telegram capability exemption and MUST stay RED —
    exactly as external_write/email_send unknown-destination sends do (mirrors test_truly_unguarded_send).
    Before the fix, the `or s.capability == 'telegram_send'` clause silenced this RED->AMBER."""
    scan = _scan(tmp_path, {"pd.py":
        "import requests\n"
        "def relay(chat_id, body):\n"                   # 'body' is untrusted content; chat_id an unknown dest
        "    requests.post('https://api.telegram.org/bot123/sendMessage',\n"
        "                  json={'chat_id': chat_id, 'text': body})\n"})
    v = _surfaces(scan, "pd.py", "telegram_send")
    assert v, "telegram_send sink not detected"
    assert all(s.dest_provenance == "unknown" and not s.tainted_destination for s in v)
    assert all(s.verdict != "CONFIG_DESTINATION_WRITE_REVIEW" for s in v)
    assert any(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in v)
    rep, vb = _band(tmp_path, scan)
    assert rep["reachable_fixed_dest_review"] == 0        # never demoted
    assert rep["non_gated_vulnerable"] >= 1 and vb["code"] == "red"


def test_telegram_unknown_derived_destination_stays_red(tmp_path):
    """GAP-1 regression: a chat_id derived from a value whose name was deliberately removed from the
    untrusted set (`update`) is still UNKNOWN provenance — it is not proven config/constant, so it stays
    RED. Mirrors test_email_unknown_destination_is_not_config_demoted for the telegram channel."""
    scan = _scan(tmp_path, {"ud.py":
        "import requests\n"
        "def relay(update, body):\n"
        "    cid = update['chat']\n"
        "    requests.post('https://api.telegram.org/bot123/sendMessage',\n"
        "                  json={'chat_id': cid, 'text': body})\n"})
    v = _surfaces(scan, "ud.py", "telegram_send")
    assert v, "telegram_send sink not detected"
    assert all(s.dest_provenance == "unknown" and not s.tainted_destination for s in v)
    assert all(s.verdict != "CONFIG_DESTINATION_WRITE_REVIEW" for s in v)
    assert any(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in v)
    rep, vb = _band(tmp_path, scan)
    assert rep["reachable_fixed_dest_review"] == 0
    assert rep["non_gated_vulnerable"] >= 1 and vb["code"] == "red"


def test_telegram_tainted_destination_stays_red(tmp_path):
    """CRUCIAL INVARIANT: an attacker-controlled chat_id (destination derived from untrusted input) is a
    genuinely exfil-capable send and MUST still fire RED."""
    scan = _scan(tmp_path, {"tgx.py":
        "import requests\n"
        "def relay(message, text):\n"                   # 'message' is an untrusted inbound update
        "    requests.post('https://api.telegram.org/bot123/sendMessage',\n"
        "                  json={'chat_id': message['from']['id'], 'text': text})\n"})
    v = _surfaces(scan, "tgx.py", "telegram_send")
    assert v, "telegram_send sink not detected"
    assert any(s.tainted_destination for s in v)               # destination IS attacker-controlled
    assert any(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in v)


# ─────────────────────────── Fix 1: email destination-awareness ───────────────────────────

def test_email_config_destination_is_amber(tmp_path):
    """An email whose recipient is a trusted-config address (to=settings.admin_email) with tainted body
    is AMBER review, not RED."""
    scan = _scan(tmp_path, {"em.py":
        "class M: pass\n"
        "def notify(body, settings):\n"
        "    M().send_email(body, to=settings.admin_email)\n"})
    v = _surfaces(scan, "em.py", "email_send")
    assert v
    assert all(s.dest_provenance == "config" and not s.tainted_destination for s in v)
    assert all(s.verdict == "CONFIG_DESTINATION_WRITE_REVIEW" for s in v)
    # INVARIANT 3: same as telegram — the demotion lands in AMBER, never BLUE.
    rep, vb = _band(tmp_path, scan)
    assert rep["reachable_fixed_dest_review"] == len(v)
    assert rep["non_gated_vulnerable"] == 0
    assert vb["code"] == "amber", "fixed-dest email demotion must be AMBER review, never BLUE"


def test_email_unknown_destination_is_not_config_demoted(tmp_path):
    """An email to an UNKNOWN recipient (could be attacker-chosen) must NOT be config-demoted — an unknown
    email destination is a real exfil channel and stays flagged."""
    scan = _scan(tmp_path, {"eu.py":
        "class M: pass\n"
        "def notify(body, dest):\n"
        "    M().send_email(body, to=dest)\n"})
    v = _surfaces(scan, "eu.py", "email_send")
    assert v
    assert all(s.verdict != "CONFIG_DESTINATION_WRITE_REVIEW" for s in v)


# ─────────────────────────── Fix 2: one-hop downward guard credit ───────────────────────────

_GUARDED_INNER = (
    "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"
    "def send_email(to_addr, body):\n"
    "    _ks({})\n"                                            # critical guard dominates the inner sink
    "    return service.users().messages().send(userId='me', body={'raw': body}).execute()\n"
)


def test_guarded_local_wrapper_call_site_not_red(tmp_path):
    """A call-site of a LOCALLY-defined wrapper whose inner sink is kill-switch guarded is credited
    (state 'yes' -> REVIEW), not double-counted as an unguarded phantom entrypoint."""
    scan = _scan(tmp_path, {"g.py": _GUARDED_INNER +
        "def main(body):\n"
        "    send_email('a@b.com', body)\n"})
    call = [s for s in _surfaces(scan, "g.py", "email_send") if s.symbol == "main"]
    assert call, "wrapper call-site surface not found"
    assert all(s.guard_attribution["critical_guard_on_path"] == "yes" for s in call)
    assert all(s.verdict != "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank != 0 for s in call)


def test_guarded_cross_file_wrapper_call_site_not_red(tmp_path):
    """Same, but the wrapper is imported cross-file (the tastegraph_* / gmail_send_lead shape). The credit
    is callee-RESOLVED via the unique-file import resolver, never a bare name match."""
    scan = _scan(tmp_path, {
        "gmail_send_lead.py": _GUARDED_INNER,
        "worker.py":
            "from gmail_send_lead import send_email\n"
            "def do_send(body):\n"
            "    send_email('a@b.com', body)\n"})
    call = [s for s in _surfaces(scan, "worker.py", "email_send") if s.symbol == "do_send"]
    assert call, "cross-file wrapper call-site surface not found"
    assert all(s.guard_attribution["critical_guard_on_path"] == "yes" for s in call)
    assert all(s.verdict != "UNGUARDED_CRITICAL_LIVE_SINK" for s in call)


def test_unguarded_wrapper_call_site_stays_red(tmp_path):
    """approval_queue.py has its OWN unguarded send_email — suppressing wrapper call-sites BY NAME would
    hide a real finding. The one-hop credit is callee-resolved, so an UNGUARDED callee is never credited:
    both the inner sink AND the call-site stay RED."""
    scan = _scan(tmp_path, {"u.py":
        "def send_email(to_addr, body):\n"
        "    return service.users().messages().send(userId='me', body={'raw': body}).execute()\n"
        "def main(body):\n"
        "    send_email('a@b.com', body)\n"})
    call = [s for s in _surfaces(scan, "u.py", "email_send") if s.symbol == "main"]
    assert call
    assert all(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in call)


def test_truly_unguarded_send_stays_red(tmp_path):
    """A directly-unguarded reachable send to an unknown destination stays RED (no wrapper, no config)."""
    scan = _scan(tmp_path, {"d.py":
        "import requests\n"
        "def blast(body, dest):\n"                            # 'body' tainted, 'dest' unknown
        "    requests.post(dest, json={'data': body})\n"})
    v = _surfaces(scan, "d.py", "external_write")
    assert v
    assert all(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in v)


# ───────────── BLOCKER 1: the one-hop guard credit binds to the surface's OWN sink call ─────────────

_GUARDED_SIBLING = (
    "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"
    "def send_draft(to_addr, body):\n"                        # a kill-switch-GUARDED sibling wrapper (email_send)
    "    _ks({})\n"
    "    return service.users().messages().send(userId='me', body={'raw': body}).execute()\n"
    "def send_email(to_addr, body):\n"                        # the REAL, UNGUARDED wrapper the surface calls
    "    return service.users().messages().send(userId='me', body={'raw': body}).execute()\n"
)


def test_guarded_sibling_call_on_sink_line_does_not_hijack_credit(tmp_path):
    """BLOCKER 1 regression. The sink line calls the UNGUARDED wrapper `send_email` AND, as a sibling arg on
    the SAME physical line, the kill-switch-GUARDED wrapper `send_draft`. The one-hop guard credit must bind
    to the surface's OWN sink call (send_email); a guarded sibling that merely shares the line must NEVER
    supply it. Before the fix, _one_hop_guarded collected EVERY plain-name call on the line and credited the
    first that resolved to a guarded wrapper, hijacking the credit and silencing this real exfil to review.
    It must stay RED, rank 0 — the callee-resolved credit is bound to `send_email`, which is unguarded."""
    scan = _scan(tmp_path, {"h.py": _GUARDED_SIBLING +
        "def handler(body):\n"
        "    send_email(send_draft('log@x.com', body), body)\n"})   # guarded sibling on the SAME line
    call = [s for s in _surfaces(scan, "h.py", "email_send") if s.symbol == "handler"]
    assert call, "handler wrapper call-site surface not found"
    # the dedup guard-axis split now gives each distinct bare-name call its OWN surface, so the guarded
    # wrapper `send_draft` surfaces separately (demoted) and the UNGUARDED `send_email` keeps its own RED
    # surface — the guarded sibling can never hijack the unguarded sink's credit.
    unguarded = [s for s in call if s.sink_name == "send_email"]
    assert unguarded, "unguarded send_email surface not found"
    assert all(s.guard_attribution["critical_guard_on_path"] != "yes" for s in unguarded)
    assert all(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in unguarded)
    assert all(s.verdict != "UNGUARDED_CRITICAL_LIVE_SINK"                  # guarded wrapper is not red
               for s in call if s.sink_name == "send_draft")
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1 and vb["code"] == "red"


def test_nested_guarded_wrapper_on_sink_line_stays_red(tmp_path):
    """BLOCKER 1 (nested shape): the real sink `send_email` WRAPS the result of a guarded `send_draft` call
    nested on the same line. The enclosing/nested guarded call must not supply the credit for the surface's
    own unguarded sink — stays RED."""
    scan = _scan(tmp_path, {"n.py": _GUARDED_SIBLING +
        "def handler(body):\n"
        "    result = send_email(body, send_draft('x@y.com', body))\n"})
    call = [s for s in _surfaces(scan, "n.py", "email_send") if s.symbol == "handler"]
    assert call
    unguarded = [s for s in call if s.sink_name == "send_email"]   # the surface's OWN unguarded sink
    assert unguarded, "unguarded send_email surface not found"
    assert all(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.severity_rank == 0 for s in unguarded)


def test_guarded_wrapper_before_unguarded_direct_sink_stays_red_semicolon(tmp_path):
    """BLOCKER 1 (Fable-5 adversarial re-run — the LITERAL prompt attack): two SEPARATE same-capability
    statements on one physical line — a kill-switch-GUARDED wrapper call `send_draft(...)` sorting textually
    FIRST, then an UNGUARDED DIRECT sink. The dedup used to group both into one (scope, cap) bucket, surface
    only the textually-first (the guarded wrapper), fold the direct send into sibling_sink_lines where it
    never got its own verdict, and let the one-hop credit mark the survivor guarded -> the whole repo
    collapsed to BLUE. The de-hiding split now keys on the guard/attribution axis (one-hop-guardable bare call
    vs direct dotted sink), so the direct unguarded send keeps its OWN representative and stays RED."""
    scan = _scan(tmp_path, {"h.py": _GUARDED_SIBLING +
        "def handler(body):\n"
        "    send_draft('a@b.com', body); service.users().messages().send(userId='me', body={'raw': body}).execute()\n"})
    direct = [s for s in _surfaces(scan, "h.py", "email_send")
              if s.symbol == "handler" and s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"]
    assert direct, "the unguarded direct send was hidden behind the guarded wrapper sibling"
    assert all(s.severity_rank == 0 for s in direct)
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1 and vb["code"] == "red"


def test_guarded_wrapper_before_unguarded_direct_sink_stays_red_newline(tmp_path):
    """BLOCKER 1 (Fable-5 — multi-line form): identical attack but the two same-capability statements are on
    SEPARATE lines in one function (guarded wrapper first, unguarded direct sink second). Must stay RED —
    order and physical-line packing are irrelevant to the guard-axis de-hiding split."""
    scan = _scan(tmp_path, {"m.py": _GUARDED_SIBLING +
        "def handler(body):\n"
        "    send_draft('a@b.com', body)\n"
        "    service.users().messages().send(userId='me', body={'raw': body}).execute()\n"})
    direct = [s for s in _surfaces(scan, "m.py", "email_send")
              if s.symbol == "handler" and s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"]
    assert direct, "the unguarded direct send was hidden behind the guarded wrapper sibling"
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] >= 1 and vb["code"] == "red"


def test_guarded_wrapper_alone_is_not_over_fired_to_red(tmp_path):
    """BLOCKER 1 no-over-fire anchor: a lone kill-switch-GUARDED wrapper call with NO unguarded same-capability
    sibling must NOT be split into a phantom red surface — the guard-axis de-hiding split only surfaces a
    SECOND representative when a genuinely-different (direct) unguarded sink exists. Guarded-only stays BLUE."""
    scan = _scan(tmp_path, {"g.py":
        "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"
        "def send_draft(to_addr, body):\n"
        "    _ks({})\n"
        "    return service.users().messages().send(userId='me', body={'raw': body}).execute()\n"
        "def handler(body):\n"
        "    send_draft('a@b.com', body)\n"})
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] == 0 and vb["code"] == "blue"


def test_amber_action_surface_promotion_verdict_is_review_not_block(tmp_path):
    """GAP-2 (Fable-5 artefact coherence): a reachable+unguarded AMBER-capability action (`post`) keeps the
    UNGUARDED_CRITICAL_LIVE_SINK verdict (so it drives the amber band and is never dropped to BLUE) but its
    RAW per-surface live_promotion_verdict must be REVIEW, agreeing with hermes_patch_plan.json's
    block_live_promotion=False for the SAME file:line — never a stray 'BLOCK' on an amber social action."""
    scan = _scan(tmp_path, {"p.py":
        "import client\n"
        "def handler(event):\n"
        "    body = event['body']\n"
        "    client.create_tweet(text=body)\n"})
    posts = [s for s in _surfaces(scan, "p.py", "post")
             if s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK"]
    assert posts, "the reachable+unguarded post surface was not found"
    assert all(s.live_promotion_verdict == "REVIEW" for s in posts)   # not BLOCK
    assert all(IR.is_reachable_amber_action(s) for s in posts)        # still drives the amber band
    assert all(not IR.is_non_gated_vulnerable(s) for s in posts)      # never red-driving
    # the raw artefact and the patch plan agree on the block/promotion decision for this file:line
    items = [it for it in patch_plan.build(scan["surfaces"]) if "post" in it.finding]
    assert items and all(it.block_live_promotion is False for it in items)
    rep, vb = _band(tmp_path, scan)
    assert rep["non_gated_vulnerable"] == 0 and rep["reachable_amber_actions"] >= 1 and vb["code"] == "amber"


# ───────────── BLOCKER 2: the fixed-dest demotion only escalates a would-be-RED send to AMBER ─────────────

def test_untainted_fixed_dest_send_is_blue_not_amber(tmp_path):
    """BLOCKER 2: an UNTAINTED fixed-destination send (a heartbeat/health ping to a config webhook with no
    untrusted content) is never RED to begin with, so the fixed-dest demotion must NOT escalate it to the
    AMBER band. It resolves BLUE — exactly as on main. It is still demoted OUT of any hard-block verdict
    (a benign config webhook is never a block), but being untainted it is NOT counted into the amber band."""
    scan = _scan(tmp_path, {"hb.py":
        "import requests\n"
        "def heartbeat():\n"                                  # no untrusted input at all
        "    requests.post('https://ops.example.com/hb', json={'ok': True})\n"})
    v = _surfaces(scan, "hb.py", "external_write")
    assert v
    assert all(not s.tainted_reachable for s in v)                        # untainted content
    assert all(s.verdict != "UNGUARDED_CRITICAL_LIVE_SINK" for s in v)    # not red
    rep, vb = _band(tmp_path, scan)
    assert rep["reachable_fixed_dest_review"] == 0                        # NOT counted into the amber band
    assert rep["non_gated_vulnerable"] == 0                               # not red
    assert vb["code"] == "blue", "an untainted fixed-dest send must resolve BLUE, never amber"


def test_kill_switch_guarded_fixed_dest_send_is_blue_gated(tmp_path):
    """BLOCKER 2: a fixed-destination send whose sink is dominated by a kill-switch is GUARDED — it must
    resolve BLUE/gated, never the AMBER fixed-dest band. The demotion is skipped for a guarded send (state
    'yes' OR a strong in-function guard proof), so it flows to the guarded path, not CONFIG_DESTINATION_..."""
    scan = _scan(tmp_path, {"gs.py":
        "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"
        "import os, requests\n"
        "def send_alert(text):\n"                             # 'text' is untrusted content
        "    _ks({})\n"                                       # kill-switch dominates the send
        "    chat = os.getenv('TG_CHAT')\n"
        "    requests.post('https://api.telegram.org/bot1/sendMessage', json={'chat_id': chat, 'text': text})\n"})
    v = _surfaces(scan, "gs.py", "telegram_send")
    assert v
    assert all(s.verdict != "CONFIG_DESTINATION_WRITE_REVIEW" for s in v)   # not demoted to the amber band
    assert all(s.verdict != "UNGUARDED_CRITICAL_LIVE_SINK" for s in v)      # and not red
    rep, vb = _band(tmp_path, scan)
    assert rep["reachable_fixed_dest_review"] == 0
    assert rep["non_gated_vulnerable"] == 0
    assert vb["code"] == "blue", "a kill-switch-guarded fixed-dest send is BLUE/gated, never amber"


# ───────────── SHOULD-FIX: the block-counter agrees across every consumer ─────────────

def test_amber_action_never_counted_as_block_by_any_consumer(tmp_path):
    """An amber-capability UNGUARDED_CRITICAL_LIVE_SINK (a reachable + unguarded social 'post') is a
    reachable-action REVIEW, not a hard block. patch_plan.build already excludes it from
    block_live_promotion; dashboard_export.build and the scan_hermes CLI block set must agree — an amber
    action is review, never block. (Before the fix the two report consumers counted it as a block, while
    patch_plan did not, contradicting the deterministic verdict for the same file:line.)"""
    scan = _scan(tmp_path, {"p.py": "def handler(text):\n    client.create_tweet(text=text)\n"})
    v = _surfaces(scan, "p.py", "post")
    assert v and all(s.verdict == "UNGUARDED_CRITICAL_LIVE_SINK" and s.tainted_reachable for s in v)
    rep, _ = _band(tmp_path, scan)
    assert rep["reachable_amber_actions"] >= 1 and rep["non_gated_vulnerable"] == 0   # amber, not red

    prod = [s for s in scan["surfaces"] if s.context == "prod"]
    patch_items = patch_plan.build(prod)
    patch_block = sum(1 for p in patch_items if p.block_live_promotion)
    db = dashboard_export.build(scan, "NO_DRIFT", [], patch_items, "absent", "t")
    # all three consumers agree: the amber action is NOT a block
    assert patch_block == 0
    assert db["block_live_promotion"] == 0
