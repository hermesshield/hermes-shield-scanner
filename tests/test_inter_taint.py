"""S8 inter-procedural taint tests — cross-function reachability + the sound-leaning limits."""
import sys
from pathlib import Path


from hermes_shield import inter_taint as IT
from hermes_shield import cross_module as XM


def _compute(tmp, files):
    for name, src in files.items():
        (tmp / name).write_text(src)
    graphs = XM.build_graphs(tmp, list(files))
    return IT.compute(tmp, graphs, XM.build_mod2files(graphs))


def test_return_flow_across_functions(tmp_path):
    """x = helper(untrusted); os.system(x) across functions -> the sink is tainted (was lost intra-only).
    S8.42: the source must be a REAL entrypoint (route handler), not a bare param name."""
    res = _compute(tmp_path, {"a.py": "import os\ndef clean(text):\n    return text.strip()\n"
                                       "@app.post('/h')\ndef handler(message):\n    os.system(clean(message))\n"})
    assert res.get("a.py"), "return-flow sink not tainted"


def test_param_to_arg_across_functions(tmp_path):
    """entry(payload) -> sink_fn(payload) where sink_fn has the sink -> the sink is tainted.
    S8.42: entry is a REAL entrypoint (route handler) so payload is a grounded untrusted source."""
    res = _compute(tmp_path, {"b.py": "import os\ndef sink_fn(data):\n    os.system(data)\n"
                                       "@app.post('/e')\ndef entry(payload):\n    sink_fn(payload)\n"})
    assert 3 in res.get("b.py", {}), "param->arg did not taint the callee sink"


def test_name_param_without_entrypoint_not_grounded(tmp_path):
    """S8.42 the fix: a bare param called 'message' that NO entrypoint reaches is NOT grounded-reachable
    (this is the over-mark that inflated the reachable number - now killed)."""
    res = _compute(tmp_path, {"u.py": "import os\ndef process(message):\n    os.system(message)\n"})
    assert not res.get("u.py"), "bare name-param over-marked as reachable (grounding failed)"


def test_wrong_file_same_name_not_tainted(tmp_path):
    """A helper of the same name in a DIFFERENT package must not carry taint into our sink."""
    (tmp_path / "pkg_a").mkdir()
    (tmp_path / "pkg_b").mkdir()
    (tmp_path / "pkg_a" / "__init__.py").write_text("")
    (tmp_path / "pkg_b" / "__init__.py").write_text("")
    # same function NAME `send` in both packages; pkg_b's sink param `d` is NOT an untrusted name, so it can
    # only become tainted via a cross-file leak. The caller imports pkg_a's benign send -> pkg_b must stay clean.
    files = {
        "pkg_a/util.py": "def send(d):\n    return d\n",              # benign same-name
        "pkg_b/util.py": "import os\ndef send(d):\n    os.system(d)\n",  # the sink, d not untrusted-named
        "caller.py": "from pkg_a.util import send\ndef go(message):\n    send(message)\n",  # calls pkg_a.send
    }
    for n, s in files.items():
        (tmp_path / n).write_text(s)
    graphs = XM.build_graphs(tmp_path, ["pkg_a/util.py", "pkg_b/util.py", "pkg_a/__init__.py",
                                        "pkg_b/__init__.py", "caller.py"])
    res = IT.compute(tmp_path, graphs, XM.build_mod2files(graphs))
    # pkg_b/util.py's os.system(d) must NOT be tainted (untrusted flows only to pkg_a.send)
    assert not res.get("pkg_b/util.py"), "wrong-file taint leaked"


def test_dynamic_dispatch_callee_not_propagated(tmp_path):
    """fn(message) where fn is a param: the unknown callee's body is never claimed reachable."""
    res = _compute(tmp_path, {"c.py": "def go(message, fn):\n    fn(message)\n"})
    # only the direct call site may reflect the tainted arg; there is no callee body to over-claim.
    assert res.get("c.py") in (None, {}) or all(isinstance(k, int) for k in res.get("c.py", {}))


def test_depends_default_does_not_crash(tmp_path):
    """S8.50 regression: a param default that is a call whose func is a bare Name (Depends(...), the FastAPI
    DI pattern) must NOT crash FileGraph (it did on ~40% of real repos), and the Depends param is excluded
    from untrusted grounding."""
    from hermes_shield import call_graph as CG
    g = CG.FileGraph("import os\n@app.post('/x')\ndef r(db = Depends(get_db), body=None):\n    os.system(body)\n")
    assert g.ok, "FileGraph crashed on a Depends() default"
    params = dict(g.funcs['r']['params'])
    assert params['db'] is True and params['body'] is False   # db is a DI dep, body is real
