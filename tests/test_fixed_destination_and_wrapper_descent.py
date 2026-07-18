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
