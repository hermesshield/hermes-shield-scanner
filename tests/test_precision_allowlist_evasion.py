#!/usr/bin/env python3
"""Regression guard for the Pass-A precision allowlist (Fable-found evasion).

The benign-infra allowlist must NEVER hide a real dangerous capability behind a
receiver that merely *looks* benign (name it `logger`/`metrics`/`tracer`/`statsd`,
or reach it via `self.api.*`). The allowlist may only quiet the GENERIC residue
(tool_invoke/unknown_action) for benign VERBS; specific sink matchers always win.

Each case is an isolated single-file repo so receiver-name binding can't leak
across functions/files. A passing full suite must not be able to hide this class."""
from __future__ import annotations

from hermes_shield import repo_scanner, surface_classifier


def _caps(tmp_path, code):
    d = tmp_path / "r"
    d.mkdir()
    (d / "app.py").write_text(code, encoding="utf-8")
    scan = repo_scanner.scan_repo(d)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    return {s.capability for s in scan["surfaces"]}


# --- FN-2: a dangerous verb on a benign-named receiver MUST still flag -----------------------
def test_cloud_write_on_logger_named_receiver_flags(tmp_path):
    assert "cloud_write" in _caps(tmp_path, "def h(d):\n    logger.put_object(d)\n")


def test_email_on_metrics_named_receiver_flags(tmp_path):
    assert "email_send" in _caps(tmp_path, "def h(t):\n    metrics.send_email(t)\n")


def test_blockchain_on_tracer_named_receiver_flags(tmp_path):
    assert "blockchain_tx" in _caps(tmp_path, "def h(tx):\n    tracer.send_transaction(tx)\n")


def test_post_on_statsd_named_receiver_flags(tmp_path):
    assert "post" in _caps(tmp_path, "def h(t):\n    statsd.create_tweet(t)\n")


def test_payment_via_stripe_aliased_to_logger_flags(tmp_path):
    code = "import stripe\ndef h(amt):\n    logger = stripe.StripeClient()\n    logger.charge(amt)\n"
    assert "payment" in _caps(tmp_path, code)


# --- FN-1: self.<attr>.<dangerous> flags; only BARE self/cls status is benign ----------------
def test_self_api_update_status_flags_post(tmp_path):
    code = "class B:\n    def h(self, t):\n        self.api.update_status(t)\n"
    assert "post" in _caps(tmp_path, code)


# --- the intended noise cut MUST survive (benign residue stays suppressed) -------------------
def test_benign_logger_warning_suppressed(tmp_path):
    assert _caps(tmp_path, "def h(m):\n    logger.warning(m)\n") == set()


def test_benign_string_split_suppressed(tmp_path):
    assert _caps(tmp_path, "def h(p):\n    return p.split(',')\n") == set()


def test_bare_self_update_status_stays_benign(tmp_path):
    code = "class B:\n    def h(self, s):\n        self.update_status(s)\n"
    assert "post" not in _caps(tmp_path, code)


# --- span/telemetry event verbs: benign on a framework-rooted span, but never a hiding place -------
# (agent_step_span.add_event / .set_attributes on a langgraph/crewai-rooted object is observability, not an
# action. It was picking up the generic tool_invoke residue and stamping RED. The allowlist quiets it —
# verb-keyed — but ONLY the generic residue; a specific sink verb still wins.)

def test_span_add_event_on_framework_object_suppressed(tmp_path):
    code = "import crewai\ndef h(a):\n    span = crewai.Tracer()\n    span.add_event(a)\n"
    assert _caps(tmp_path, code) == set()


def test_span_set_attributes_suppressed(tmp_path):
    code = "import crewai\ndef h(a):\n    span = crewai.Tracer()\n    span.set_attributes(a)\n"
    assert _caps(tmp_path, code) == set()


def test_self_span_record_exception_suppressed(tmp_path):
    code = ("import crewai\nclass B:\n    def __init__(self):\n        self.span = crewai.Tracer()\n"
            "    def h(self, e):\n        self.span.record_exception(e)\n")
    assert _caps(tmp_path, code) == set()


def test_span_verb_does_not_hide_email_sink(tmp_path):
    # a DANGEROUS specific verb on a span-named receiver must still flag its specific capability —
    # the span allowlist only ever quiets the generic residue, never a resolved sink.
    assert "email_send" in _caps(tmp_path, "def h(t):\n    agent_step_span.send_email(t)\n")


def test_span_verb_does_not_hide_cloud_write_sink(tmp_path):
    assert "cloud_write" in _caps(tmp_path, "def h(d):\n    agent_step_span.put_object(d)\n")


# --- taxonomy coverage: an LLM-adapter invocation is a READ-ONLY model_call, never UNSTAMPED ---------
# (llm_adapter.invoke_llm had no matcher and fell through unstamped, leaving a coverage gap; its peers —
# chat/completions .create — are read-only model_call, so it is restored to the same read-only stamp.)

def test_invoke_llm_stamps_read_only_model_call(tmp_path):
    assert _caps(tmp_path, "def h(p):\n    return llm_adapter.invoke_llm(p)\n") == {"model_call"}


def test_invoke_llm_is_never_red(tmp_path):
    # model_call is read-only: it must never reach the RED non-gated-vulnerable set.
    from hermes_shield import install_report as IR
    d = tmp_path / "r"; d.mkdir()
    (d / "app.py").write_text("def h(p):\n    return llm_adapter.invoke_llm(p)\n", encoding="utf-8")
    scan = repo_scanner.scan_repo(d)
    for s in scan["surfaces"]:
        surface_classifier.classify(s)
    assert not any(IR.is_non_gated_vulnerable(s) for s in scan["surfaces"])
