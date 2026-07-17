"""S8.23 field + container taint — real self.field/container paths become reachable; non-paths stay clean."""
import sys
from pathlib import Path


from hermes_shield import inter_taint as IT, cross_module as XM


def _compute(tmp, files):
    for name, src in files.items():
        (tmp / name).write_text(src)
    g = XM.build_graphs(tmp, list(files))
    return IT.compute(tmp, g, XM.build_mod2files(g))


# --- class field-cell (cross-method) ---
# S8.42: the receiving method must be a REAL entrypoint (event handler) for its param to be a grounded
# untrusted source — the receive()->act() agent-injection shape with a real entry contract.
def test_field_store_then_act(tmp_path):
    r = _compute(tmp_path, {"a.py": "import os\nclass Agent:\n    def on_message(self, message):\n        self.pending = message\n    def act(self):\n        os.system(self.pending)\n"})
    assert r.get("a.py"), "on_message()->act() field flow not reachable"


def test_field_init_seed(tmp_path):
    r = _compute(tmp_path, {"b.py": "import os\nclass Agent:\n    def on_event(self, payload):\n        self.buf = payload\n    def run(self):\n        os.system(self.buf)\n"})
    assert r.get("b.py")


def test_field_constant_not_tainted(tmp_path):
    r = _compute(tmp_path, {"c.py": "import os\nclass Agent:\n    def s(self):\n        self.buf = 'safe'\n    def run(self):\n        os.system(self.buf)\n"})
    assert not r.get("c.py")


def test_field_different_field_not_tainted(tmp_path):
    r = _compute(tmp_path, {"d.py": "import os\nclass Agent:\n    def s(self, message):\n        self.a = message\n    def run(self):\n        os.system(self.b)\n"})
    assert not r.get("d.py")


def test_field_different_class_not_tainted(tmp_path):
    r = _compute(tmp_path, {"e.py": "import os\nclass A:\n    def s(self, message):\n        self.buf = message\nclass B:\n    def run(self):\n        os.system(self.buf)\n"})
    assert not r.get("e.py")


# --- containers (intra-function, via analyze) ---
import ast
from hermes_shield import taint as T


def _sink_tainted(src):
    hits = T.analyze(ast.parse(src))
    line = None
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "system":
            line = n.lineno
    return line in hits


def test_list_append_flow(tmp_path):
    assert _sink_tainted("import os\ndef f(message):\n    buf = []\n    buf.append(message)\n    os.system(buf[0])\n")


def test_dict_assign_flow(tmp_path):
    assert _sink_tainted("import os\ndef f(message):\n    d = {}\n    d['k'] = message\n    os.system(d['k'])\n")


def test_clean_container_not_tainted(tmp_path):
    assert not _sink_tainted("import os\ndef f():\n    buf = []\n    buf.append('safe')\n    os.system(buf[0])\n")


def test_aliased_container_under_claimed(tmp_path):
    assert not _sink_tainted("import os\ndef f(message):\n    buf = []\n    alias = buf\n    alias.append(message)\n    os.system(buf[0])\n")
