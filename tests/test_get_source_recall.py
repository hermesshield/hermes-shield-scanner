"""Recall fix: `request.args.get("x")` / `.getlist(...)` are untrusted sources (the common Flask/FastAPI
idiom), while innocent `dict.get`/`os.environ.get`/`cfg.get` stay quiet. Additive — nothing removed."""
import ast
import textwrap

from hermes_shield.taint import _is_source_call, analyze


def _call(src):
    return ast.parse(src, mode="eval").body


def test_request_scoped_get_is_untrusted_source():
    for src in ("request.args.get('cmd')", "request.form.get('x')", "request.json.get('x')",
                "req.query_params.get('x')", "request.args.getlist('x')", "request.values.get('x', '')"):
        assert _is_source_call(_call(src)) is True, src


def test_innocent_get_stays_quiet():
    for src in ("dict.get('k')", "os.environ.get('PATH')", "cfg.get('k')", "cache.get(key)",
                "settings.get('debug')", "d.get('x', 0)"):
        assert _is_source_call(_call(src)) is False, src


def test_flask_get_flows_to_sink_end_to_end():
    # request.json.get(...) → eval : must be tainted-reachable (was MISSED before the fix).
    code = textwrap.dedent(
        """
        def run():
            task = request.json.get("task")
            return eval(task)
        """
    )
    fn = ast.parse(code).body[0]
    tainted = analyze(fn)
    # the eval() call line must be reported as tainted-from-source
    assert tainted, "expected the eval sink to be tainted via request.json.get()"


def test_bracket_and_get_forms_agree():
    # the .get() form and the [] form should both be untrusted sources (parity).
    assert _is_source_call(_call("request.args.get('c')")) is True
    assert _is_source_call(ast.parse("request.args['c']", mode="eval").body) is True
