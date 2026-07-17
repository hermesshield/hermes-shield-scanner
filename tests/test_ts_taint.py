"""S8.27 TypeScript taint — real flows become reachable; operator-controlled/aliased/other stay clean."""
import sys
from pathlib import Path


import pytest

pytest.importorskip("tree_sitter_typescript", reason="optional multilang extra not installed")

from hermes_shield import ts_taint as T


def _hit(src):
    return bool(T.analyze(src))


def _eval_line_tainted(src):
    m = T.analyze(src)
    import tree_sitter_typescript as tsts
    from tree_sitter import Language, Parser
    b = src.encode()
    tree = Parser(Language(tsts.language_typescript())).parse(b)
    ln = None
    for n in T._walk(tree.root_node):
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn and fn.type == "identifier" and b[fn.start_byte:fn.end_byte].decode() == "eval":
                ln = n.start_point[0] + 1
    return ln in m


# true positives
def test_assign_flow():
    assert _hit("function f(body){ const c = body.path; eval(c); }")


def test_req_body_source():
    assert _hit("function h(req,res){ eval(req.body.cmd); }")


def test_await_json_source():
    assert _hit("async function f(res){ const j = await res.json(); eval(j.cmd); }")


def test_array_push_flow():
    assert _hit("function f(body){ const a=[]; a.push(body.x); eval(a[0]); }")


def test_field_store_then_act():
    assert _hit("class W{ onMessage(msg){ this.pending = msg.content; } act(){ eval(this.pending); } }")


# true negatives (no false claim)
def test_process_env_not_source():
    assert not _hit("function f(){ eval(process.env.CMD); }")


def test_process_argv_not_source():
    assert not _hit("function f(){ eval(process.argv[2]); }")


def test_generic_param_not_source():
    assert not _hit("function f(data){ eval(data); }")


def test_constant_clean():
    assert not _hit("function f(){ const c='ls'; eval(c); }")


def test_different_class_clean():
    assert not _hit("class A{ s(msg){ this.buf=msg; } } class B{ run(){ eval(this.buf); } }")


def test_aliased_container_under_claimed():
    # the alias push line carries taint, but the actual eval(a[0]) sink must NOT (a is not tainted)
    assert not _eval_line_tainted("function f(body){\n const a=[];\n const b=a;\n b.push(body.x);\n eval(a[0]);\n}")
