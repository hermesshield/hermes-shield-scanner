"""S8 upgrade #1: structural-pattern absorption — generalises to the resolved MODULE family, never the verb."""
import sys
from pathlib import Path


from hermes_shield import repo_scanner, ast_sinks, learned_sinks


def _clean():
    for r in list(learned_sinks.structural_rules()):
        learned_sinks.revert(r["id"])
    ast_sinks.reload_learned()


def test_generalises_to_module_family(tmp_path):
    """Absorbing one subprocess verb catches OTHER subprocess-family verbs (module_wide), even under an alias."""
    _clean()
    (tmp_path / "a.py").write_text("import subprocess as sp\ndef h(msg):\n    sp.run_shell(msg)\n")
    learned_sinks.add_structural({"capability": "subprocess_exec", "module_root": "subprocess",
                                  "verb": "check_call", "provenance": {"repo": "t"}})
    ast_sinks.reload_learned()
    hits = [s for s in repo_scanner.scan_repo(tmp_path)["surfaces"] if s.capability == "subprocess_exec"]
    _clean()
    assert hits, "structural rule did not generalise to the subprocess family"


def test_no_false_positive_on_local_object(tmp_path):
    """The SAME verb on a local object (not the resolved module) must NOT fire."""
    _clean()
    (tmp_path / "b.py").write_text("def f(x):\n    obj = make()\n    obj.run_shell(x)\n")
    learned_sinks.add_structural({"capability": "subprocess_exec", "module_root": "subprocess",
                                  "verb": "check_call", "provenance": {"repo": "t"}})
    ast_sinks.reload_learned()
    hits = [s for s in repo_scanner.scan_repo(tmp_path)["surfaces"]
            if s.file_path == "b.py" and s.capability == "subprocess_exec"]
    _clean()
    assert not hits, "structural rule falsely fired on a local object"


def test_denylisted_module_rejected():
    """Mixed/grab-bag modules (os) are NOT absorbed as structural rules (would fire on os.getcwd)."""
    _clean()
    rid = learned_sinks.add_structural({"capability": "subprocess_exec", "module_root": "os",
                                        "verb": "system", "provenance": {}})
    _clean()
    assert rid is None, "denylisted module was wrongly absorbed"


def test_soft_module_needs_distinctive_verb():
    """A non-hard module absorbs verb_set only with a distinctive verb (not a generic one)."""
    _clean()
    generic = learned_sinks.add_structural({"capability": "external_write", "module_root": "myclient",
                                            "verb": "get", "provenance": {}})
    distinctive = learned_sinks.add_structural({"capability": "external_write", "module_root": "myclient",
                                                "verb": "transfer_funds", "provenance": {}})
    _clean()
    assert generic is None and distinctive is not None
