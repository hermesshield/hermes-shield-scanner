#!/usr/bin/env python3
"""P2.9E-REVIEW — independent audit of AST sink detection + dedup-to-strongest. Includes the review
fix: an unguarded sibling sink of the same capability must NOT be hidden by a guarded sibling.
Read-only; no live actions."""
from __future__ import annotations
import sys
from pathlib import Path


from hermes_shield import repo_scanner, surface_classifier, ast_sinks  # noqa: E402

_KS = "from hermes_global_kill_switch import assert_live_action_allowed as _ks\n"


def _scan(tmp, code):
    (tmp / "a.py").write_text(code)
    scan = repo_scanner.scan_repo(tmp)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return scan["surfaces"]


# ---- the dedup-hiding fix (highest-risk P2.9E change) ---------------------------------------
def test_01_unguarded_sibling_not_hidden_by_guarded(tmp_path):
    s = _scan(tmp_path, _KS +
              "def f(x):\n    if x:\n        client.create_tweet(text='UNGUARDED')\n"
              "    try:\n        _ks({})\n    except Exception:\n        raise\n    client.create_tweet(text='guarded')\n")
    posts = [x for x in s if x.capability == "post"]
    assert len(posts) >= 2  # BOTH the guarded and the unguarded post are surfaced
    assert any(p.guard_proof.get("status") == "proven" for p in posts)
    assert any(p.guard_proof.get("status") != "proven" for p in posts)


def test_02_all_guarded_siblings_merge(tmp_path):
    # two create_tweet, BOTH after one dominating guard -> both guarded -> merged to one proven surface
    s = _scan(tmp_path, _KS +
              "def f():\n    try:\n        _ks({})\n    except Exception:\n        raise\n"
              "    client.create_tweet(text='a')\n    client.create_tweet(text='b')\n")
    posts = [x for x in s if x.capability == "post"]
    assert len(posts) == 1 and posts[0].guard_proof["status"] == "proven"


# ---- AST structural exclusion --------------------------------------------------------------
def test_03_import_line_not_sink(tmp_path):
    s = _scan(tmp_path, "from investor_finder.gmail_send_lead import send_email\ndef r():\n    return send_email\n")
    assert not any(x.capability == "email_send" for x in s)


def test_04_def_line_not_sink(tmp_path):
    s = _scan(tmp_path, "def create_tweet(t):\n    return t\n")
    assert not any(x.capability == "post" for x in s)


def test_05_string_only_sql_not_live(tmp_path):
    s = _scan(tmp_path, "def b():\n    q = \"UPDATE x_post_queue SET status='x'\"\n    return q\n")
    assert not any(x.capability in ("queue_mutation", "db_mutation") for x in s)


def test_06_sql_execute_call_detected(tmp_path):
    s = _scan(tmp_path, "def a(c):\n    c.execute(\"UPDATE x_post_queue SET status='x'\")\n")
    assert any(x.capability == "queue_mutation" for x in s)


def test_07_requests_get_read_only(tmp_path):
    s = _scan(tmp_path, "import requests\ndef g(u):\n    return requests.get(u).json()\n")
    caps = {x.capability for x in s}
    assert "external_read" in caps and "external_write" not in caps


def test_08_module_scope_call_detected(tmp_path):
    ok, sinks = ast_sinks.detect("import requests\nrequests.post('u', json={})\n")
    assert ok and any(sk["module_scope"] and sk["capability"] == "external_write" for sk in sinks)


# ---- regressions from P2.9D ---------------------------------------------------------------
def test_09_cond_raise_stays_unprotected(tmp_path):
    s = _scan(tmp_path, _KS + "def f(bad):\n    try:\n        _ks({})\n    except Exception:\n        if bad:\n            raise\n        log('x')\n    client.create_tweet(text='x')\n")
    p = [x for x in s if x.capability == "post"][0]
    assert p.guard_proof["status"] != "proven"


def test_10_finally_sink_stays_unprotected(tmp_path):
    s = _scan(tmp_path, _KS + "def f():\n    try:\n        _ks({})\n    except Exception:\n        raise\n    finally:\n        client.create_tweet(text='x')\n")
    p = [x for x in s if x.capability == "post"][0]
    assert p.guard_proof["status"] != "proven"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
