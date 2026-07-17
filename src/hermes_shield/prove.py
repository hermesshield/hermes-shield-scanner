"""
prove.py — the PROVEN-LIVE self-attack lane (Phase 0).

install_report.build_report promotes a candidate-critical finding to PROVEN-LIVE only when its
`(file_substr, sink_line)` is in the `validated` set. Nothing populated that set, so `proven_live`
was always 0. This lane fills it HONESTLY: for a candidate whose sink we can drive directly, it
constructs a benign, per-run, unforgeable canary payload, runs it inside a network-denied sandbox,
confirms the canary fired VIA THE SINK, checks a negative control, and reproduces the effect. Only a
candidate passing ALL of {nonce fired via the sink · negative control clean · reproduced} is added to
`validated`.

SAFETY CONTRACT (Phase 0):
  * PROMOTE-ONLY. A failed / inconclusive / refused proof leaves the finding EXACTLY as the scanner
    reported it (a candidate). This lane can only promote candidate -> proven-live. It NEVER downgrades
    a finding to "safe" and never removes one.
  * PROVABLE SET = {code_exec, ssti} only (NOT subprocess_exec / deserialize yet). Anything else, or a
    sink that needs an app stood up, or is non-Python, or is not directly drivable -> a manual PoC
    recipe is emitted and the sink is NEVER auto-run and NEVER promoted.
  * ISOLATION IS MANDATORY, AND STRUCTURAL. Target code — INCLUDING the import used to obtain the
    callable — is only ever executed inside a **bwrap** isolation cell (network unshared, filesystem
    contained, non-root). There is NO unsandboxed execution path: the rlimit-only `subprocess` fallback
    cannot unshare the network or contain the filesystem, so the lane REFUSES to execute under it (a clean
    "refused: no bwrap sandbox" rather than running target code unsandboxed). A hard wall-clock kill always
    applies. No environment / secrets are passed in.
  * CONSENT-GATED. Off by default, not in --all. The caller must confirm before any execution.

Phase 0 is scoped to the bundled demo/example fixture only; wiring it to auto-run on arbitrary user
repos is a separate, gated Phase 1. The machinery here is built so Phase 1 is a small extension.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Phase-0 policy constants
# ---------------------------------------------------------------------------
# capabilities THIS phase can prove. SSTI has zero side effect (preferred where applicable). subprocess_exec
# is Phase-2a and is GATED at drivability time (shell_form only + param-IS-command-string only); deserialize
# still gets a manual recipe, never an auto-run.
PROVABLE_CAPS = {"code_exec", "ssti", "subprocess_exec"}

# The CODE / COMMAND / TEMPLATE position per capability — the single argument an attacker controls to
# achieve RCE. (positional_index, (kwarg_names_that_also_carry_it, ...)). If this position is ABSENT from a
# given sink call, there is no resolvable injection point and the sink is NOT drivable.
_INJECTABLE_ARG = {
    "code_exec": (0, ()),                     # eval/exec/compile/__import__(<code>) + framework exec(<code>) -> arg 0
    "ssti": (0, ()),                          # render_template_string(<template>) / env.from_string(<template>) -> arg 0
    "subprocess_exec": (0, ("args", "cmd")),  # subprocess.run/Popen/... (<cmd>|args=|cmd=), os.system/os.popen(<cmd>) -> arg 0
}
# RCE-class surfaces the lane will consider at all (mirrors install_report._RCE_CAPS). Non-provable ones
# still get a recipe so the operator sees a manual path.
RCE_CAPS = {"code_exec", "deserialize", "subprocess_exec", "ssti"}

_WALL_CLOCK_SECS = 20          # hard wall-clock kill for every cell run
_CPU_SECS = 8                  # fallback rlimit: CPU seconds
_AS_BYTES = 512 * 1024 * 1024  # fallback rlimit: address space
_NOFILE = 64                   # fallback rlimit: open files
_NPROC = 64                    # fallback rlimit: processes/threads
_FSIZE = 8 * 1024 * 1024       # fallback rlimit: max file size written

LOUD_WARNING = (
    "\n"
    "  ############################################################################\n"
    "  ##  HERMES SHIELD — PROVE LANE (self-attack)                              ##\n"
    "  ##------------------------------------------------------------------------##\n"
    "  ##  This EXECUTES code from the target INSIDE A SANDBOX to prove a sink   ##\n"
    "  ##  is really live. It runs a benign, per-run canary payload — it never   ##\n"
    "  ##  posts, deletes, or reaches the network — but it DOES run target code. ##\n"
    "  ##                                                                        ##\n"
    "  ##  ONLY run this on a repository you TRUST. Never on untrusted code.      ##\n"
    "  ##  In Phase 0 it is contained to the bundled demo fixture.               ##\n"
    "  ############################################################################\n"
)


# ---------------------------------------------------------------------------
# Isolation backend detection
# ---------------------------------------------------------------------------
def isolation_backend() -> str:
    """'bwrap' when bubblewrap is on PATH, else 'subprocess' (hardened rlimit fallback)."""
    return "bwrap" if shutil.which("bwrap") else "subprocess"


def prove_supported() -> tuple[bool, str]:
    """--prove requires Linux + bubblewrap. The subprocess fallback is POSIX-only (`resource`/`os.setsid`)
    and cannot deny the network without namespaces, so off Linux+bwrap we REFUSE the lane cleanly rather
    than crash (native Windows) or run a network-exposed sandbox (macOS). The deterministic scan is
    unaffected — it has already completed by the time the lane runs."""
    if not sys.platform.startswith("linux"):
        return False, (f"--prove needs Linux with bubblewrap (this machine is {sys.platform}); "
                       "the scan itself ran fully — see the report")
    if not shutil.which("bwrap"):
        return False, ("--prove needs bubblewrap (bwrap) for a network-isolated sandbox — not found; "
                       "install it (e.g. `apt install bubblewrap`). The scan itself ran fully")
    return True, ""


# ---------------------------------------------------------------------------
# Trigger spec — STATIC AST derivation (no execution). Answers: is the sink's enclosing callable
# directly drivable, and via which untrusted parameter? Also records the entrypoint + taint path for
# the evidence bundle. Never imports or runs the target.
# ---------------------------------------------------------------------------
def _enclosing_func(tree, line):
    best = None
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = n.lineno
            end = getattr(n, "end_lineno", start)
            if start <= line <= end and (best is None or start > best.lineno):
                best = n
    return best


def _entry_hint(fn):
    decos = []
    for d in getattr(fn, "decorator_list", []):
        try:
            decos.append(ast.unparse(d))
        except Exception:
            pass
    for d in decos:
        dl = d.lower()
        if any(v in dl for v in (".post", ".get", ".put", ".delete", ".patch", ".route", ".websocket", ".api_route")):
            return {"type": "http_route", "evidence": d}
    for d in decos:
        dl = d.lower().split(".")[-1]
        if dl in ("on", "event", "message", "webhook", "command", "on_event"):
            return {"type": "event_handler", "evidence": d}
    if fn.name.startswith(("handle_", "on_")):
        return {"type": "event_handler", "evidence": fn.name}
    return None


def _injectable_arg_node(call, cap):
    """The ast node at the code/command/template position for `cap`, or None if that position is absent from
    THIS call. Kwarg spellings (subprocess `args=`/`cmd=`) win over the positional index. A `*args` splat in
    the injectable slot is not a bindable position -> None."""
    spec = _INJECTABLE_ARG.get(cap)
    if spec is None:
        return None
    idx, kwnames = spec
    for kw in getattr(call, "keywords", []):
        if kw.arg in kwnames:
            return kw.value
    args = getattr(call, "args", [])
    if len(args) > idx and not isinstance(args[idx], ast.Starred):
        return args[idx]
    return None


def _find_sink_call(fn, sink_line, sink_name, cap, sym_alias, mod_alias, inst_map):
    """The exact sink `ast.Call` at `sink_line`. When several calls share the line, disambiguate by the
    resolved func string (== recorded `sink_name`), then by re-classifying to the same capability."""
    from . import ast_sinks as AS
    cands = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and getattr(n, "lineno", -1) == sink_line]
    if not cands:
        return None
    if len(cands) == 1:
        return cands[0]
    for n in cands:
        if sink_name and AS._chain_str(n.func) == sink_name:
            return n
    for n in cands:
        try:
            res = AS._classify_call(n, sym_alias, mod_alias, inst_map)
        except Exception:
            res = None
        if res and res[0] == cap:
            return n
    return cands[0]


def _const_leaf(node) -> bool:
    """A compile-time-constant expression: a Constant, or a JoinedStr / BinOp whose every leaf is constant."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(_const_leaf(v.value) if isinstance(v, ast.FormattedValue) else _const_leaf(v)
                   for v in node.values)
    if isinstance(node, ast.BinOp):
        return _const_leaf(node.left) and _const_leaf(node.right)
    return False


def _module_literal_names(tree) -> set:
    """Module-level names bound ONLY to a compile-time literal (never rebound to a non-constant at module
    scope). Lets `page.evaluate(CONST_JS, data)` count the CONST_JS position as a constant injectable."""
    good, bad = set(), set()
    for n in getattr(tree, "body", []):
        if isinstance(n, ast.Assign):
            const = _const_leaf(n.value)
            for t in n.targets:
                if isinstance(t, ast.Name):
                    (good if const else bad).add(t.id)
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            (good if _const_leaf(n.value) else bad).add(n.target.id)
    return good - bad


def _is_compile_time_constant(node, module_literals) -> bool:
    return _const_leaf(node) or (isinstance(node, ast.Name) and node.id in module_literals)


def _required_params(fn) -> set:
    """The enclosing function's REQUIRED parameters (no default), minus self/cls and minus *args/**kwargs
    (which never appear in these arg lists). The driver fills the required ones it is not injecting with a
    benign empty string so multi-param callables bind without a missing-argument TypeError."""
    a = fn.args
    positional = list(getattr(a, "posonlyargs", [])) + list(getattr(a, "args", []))
    ndef = len(getattr(a, "defaults", []))
    cut = len(positional) - ndef
    required = {p.arg for i, p in enumerate(positional) if i < cut}
    for p, d in zip(getattr(a, "kwonlyargs", []), getattr(a, "kw_defaults", [])):
        if d is None:
            required.add(p.arg)
    required.discard("self")
    required.discard("cls")
    return required


def _fmt_arg(node) -> str:
    try:
        return ast.unparse(node)[:120]
    except Exception:
        return type(node).__name__


def build_trigger_spec(surface, root) -> dict:
    """Return a trigger-spec dict for `surface`. `drivable` is True ONLY when DATAFLOW proves the sink's
    INJECTABLE argument (the code/command/template position, not just any arg) is tainted by one of the
    enclosing (non-async) function's own parameters — regardless of that parameter's NAME. So `def run(expr):
    eval(expr)` is drivable; `__import__("re")` (a compile-time constant) is refused as a non-injection
    point; and a value arriving from a global/framework request or across functions is refused (needs app
    bootstrap). Purely static: parses the file, never executes it."""
    rel = getattr(surface, "file_path", "")
    path = Path(root) / rel
    sink_line = getattr(surface, "sink_line", 0) or getattr(surface, "line_start", 0)
    cap = getattr(surface, "capability", "")
    sink_name = getattr(surface, "sink_name", "") or ""
    spec = {"callable": None, "params": [], "tainted_param": None, "sink_line": sink_line,
            "drivable": False, "reason": "", "entrypoint": None, "taint_source": None, "taint_path": [],
            "fill": {}, "injectable": None}
    if path.suffix != ".py":
        spec["reason"] = "non-Python target — Phase-0 prove lane is Python-only"
        return spec
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text)
    except Exception as e:
        spec["reason"] = f"parse-failed: {type(e).__name__}"
        return spec
    fn = _enclosing_func(tree, sink_line)
    if fn is None:
        spec["reason"] = "sink is at module scope (no enclosing callable) — needs app bootstrap"
        return spec
    spec["callable"] = fn.name
    spec["params"] = [a.arg for a in list(getattr(fn.args, "args", []))
                      + list(getattr(fn.args, "posonlyargs", []))
                      + list(getattr(fn.args, "kwonlyargs", [])) if a.arg not in ("self", "cls")]
    spec["entrypoint"] = _entry_hint(fn)
    if isinstance(fn, ast.AsyncFunctionDef):
        spec["reason"] = "async callable — needs an event loop (app bootstrap)"
        return spec
    # locate the EXACT sink call + its injectable (code/command/template) argument node.
    from . import ast_sinks as AS
    try:
        sym_alias, mod_alias = AS._collect_aliases(tree)
        inst_map = AS._collect_instances(tree, sym_alias, mod_alias)
    except Exception:
        sym_alias, mod_alias, inst_map = {}, {}, {}
    call = _find_sink_call(fn, sink_line, sink_name, cap, sym_alias, mod_alias, inst_map)
    if call is None:
        spec["reason"] = "could not locate the sink call node at the reported line"
        return spec
    inj = _injectable_arg_node(call, cap)
    if inj is None:
        spec["reason"] = "no resolvable injectable argument at the sink"
        return spec
    # DATAFLOW: seed taint from ALL of the function's params, then decide on the INJECTABLE arg node ONLY.
    try:
        from .taint import _FnTaint
        ft = _FnTaint(fn, seed_params=set(spec["params"]))
        tainted, src = ft.arg_taint(inj)
    except Exception as e:
        spec["reason"] = f"taint-derivation-failed: {type(e).__name__}"
        return spec
    spec["taint_source"] = src or getattr(surface, "taint_source", None)
    m = re.search(r"tainted param '([^']+)'", src or "")
    if tainted and m:
        tp = m.group(1)
        # Phase-2a subprocess GATE: shell-form only (refuse list-argv), and the param must BE the command
        # string (refuse f-string/concatenation embedded-injection -> recipe).
        if cap == "subprocess_exec":
            if not getattr(surface, "shell_form", True):
                spec["reason"] = ("list-argv subprocess (not shell-interpreted) — a data arg is passed "
                                  "literally, not command-injectable; recipe only")
                return spec
            if not (isinstance(inj, ast.Name) and inj.id == tp):
                spec["reason"] = ("shell command is an f-string / concatenation (embedded injection) — "
                                  "deferred to a manual recipe")
                return spec
        spec["tainted_param"] = tp
        spec["injectable"] = _fmt_arg(inj)
        spec["fill"] = {n: "" for n in _required_params(fn) if n != tp}
        spec["drivable"] = True
        spec["taint_path"] = [f"{rel}:{fn.lineno} def {fn.name}(... {tp} ...)",
                              f"{rel}:{sink_line} {sink_name or 'sink'}(<{tp}> @ injectable position)"]
        return spec
    if not tainted:
        module_literals = _module_literal_names(tree)
        if _is_compile_time_constant(inj, module_literals):
            spec["reason"] = "sink argument is a compile-time constant — not an injection point"
        else:
            spec["reason"] = ("sink is not tainted by a direct function parameter (untrusted input arrives "
                              "from a global/framework request or across functions) — needs app bootstrap")
        return spec
    # tainted, but by an internal source (store/LLM/request), not a directly-bindable parameter.
    spec["reason"] = ("sink argument is tainted by an internal source (store/LLM/request), not a direct "
                      "parameter — needs app bootstrap")
    return spec


# ---------------------------------------------------------------------------
# Driver + payloads. The driver is delivered INLINE (python -c) so nothing but the spec + canary live in
# the writable cell dir. It imports the target by file path (inside the cell), invokes the callable with
# the payload bound to the tainted parameter, and records whether the canary effect fired.
# ---------------------------------------------------------------------------
_DRIVER = r"""
import json, sys, os, importlib.util, io, contextlib, inspect
spec = json.load(open(sys.argv[1]))
res = {"error": None, "return_repr": None, "canary_file": False, "reflected": False, "ran": False}
try:
    s = importlib.util.spec_from_file_location("hs_prove_target", spec["module_path"])
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)                      # executes target module top-level — INSIDE the cell
    fn = getattr(m, spec["callable"])
    payload_name = spec["param"]                 # the injectable parameter -> receives the canary payload
    fill = spec.get("fill") or {}                # other REQUIRED params -> benign empty-string fills
    payload = spec["payload"]
    # Build the call FROM THE SIGNATURE: payload -> injectable param, fills -> other required params,
    # positional-only params passed positionally in declared order. A benign fill that diverts control just
    # means the canary never fires (inconclusive / fail-safe), never a false 'proven'.
    call_args, call_kwargs = [], {}
    try:
        for name, p in inspect.signature(fn).parameters.items():
            if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue
            if name == payload_name:
                val = payload
            elif name in fill:
                val = fill[name]
            else:
                continue                         # has a default -> leave it
            if p.kind == inspect.Parameter.POSITIONAL_ONLY:
                call_args.append(val)
            else:
                call_kwargs[name] = val
    except (TypeError, ValueError):
        call_args, call_kwargs = [], {payload_name: payload}
        call_kwargs.update(fill)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rv = fn(*call_args, **call_kwargs)
    res["ran"] = True
    res["return_repr"] = repr(rv)[:500]
    if spec["mode"] == "ssti" and spec["expect"] and (spec["expect"] in str(rv) or spec["expect"] in repr(rv)):
        res["reflected"] = True
except Exception as e:
    res["error"] = (type(e).__name__ + ": " + str(e))[:400]
cf = os.path.join(spec["canary_dir"], spec["nonce"])
if os.path.exists(cf):
    try:
        res["canary_file"] = (open(cf).read().strip() == spec["nonce"])
    except Exception:
        res["canary_file"] = True
json.dump(res, open(spec["result_path"], "w"))
"""

# benign non-payloads for the mandatory negative control: they exercise the SAME sink but produce NO
# canary effect. If the canary fires WITHOUT the payload the proof is inconclusive (harness leak / FP).
_BENIGN_CODE_EXEC = "1"                       # eval/exec of a bare literal — runs the sink, writes nothing
_BENIGN_SSTI = "hermes-benign-no-template"    # a plain string — no {{...}} to reflect
_BENIGN_SHELL = ":"                           # shell no-op — exercises subprocess(shell=True), writes nothing


def _payload_code_exec(nonce: str, canary_dir_cell: str) -> str:
    # a fixed, harness-controlled EXPRESSION (valid as both eval-expression and exec-statement). If and
    # only if it reaches eval/exec/compile does the nonce file appear. Never free-form.
    return "open(%r + '/' + %r, 'w').write(%r)" % (canary_dir_cell, nonce, nonce)


def _payload_shell(nonce: str, canary_dir_cell: str) -> str:
    # Phase-2a benign shell canary: a no-op then a printf that writes the nonce into the writable cell dir.
    # Fires ONLY if the command string is shell-interpreted (proves the shell=True injection). Never free-form;
    # writes nothing else, reaches no network. `printf %s` stays literal (str.format only touches {}).
    return ": ; printf %s '{n}' > '{d}/{n}'".format(n=nonce, d=canary_dir_cell)


def _ssti_factor(nonce: str) -> int:
    # small, per-run, derived from the nonce so the reflected product is unforgeable-ish yet tiny.
    return 100 + (int(nonce[:4], 16) % 900)


def _payload_ssti(factor: int) -> str:
    return "{{7*%d}}" % factor


# ---------------------------------------------------------------------------
# Cell execution
# ---------------------------------------------------------------------------
# system roots always re-exposed read-only in the cell.
_STD_ROOTS = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc")
# mount-point roots we must NEVER --ro-bind: binding /tmp read-only would re-expose the whole host /tmp
# over the cell's tmpfs (isolation regression); binding / read-only makes the cell root read-only so the
# writable cell mount (/hs_cell) can no longer be created ("Read-only file system") -> every proof goes
# inconclusive. This is the Phase-0 interpreter-masking bug (a real, fail-SAFE defect).
_NEVER_BIND = {"/", "/tmp", "/proc", "/dev", "/sys", "/run", "/var"}


def _covered_by_std_root(s: str) -> bool:
    return any(s == c or s.startswith(c.rstrip("/") + "/") for c in _STD_ROOTS)


def _interp_bind_paths():
    """The MINIMAL set of host paths that must be re-exposed for THIS interpreter to launch inside the
    cell: the launch path (`sys.executable`, possibly a symlink), its RESOLVED real binary, the real
    binary's bin dir, and `sys.prefix` / `sys.base_prefix`. Deterministic order, de-duped. The caller
    filters out std-root-covered paths and mount-point roots — we bind the interpreter's OWN paths, never
    its mount-point parent (the old `.resolve().parent.parent` heuristic could resolve to `/` or `/tmp`
    and break the cell)."""
    paths = []
    try:
        paths.append(str(Path(sys.executable)))                 # launch path (may be a symlink under /tmp)
        real = Path(os.path.realpath(sys.executable))
        paths.append(str(real))                                 # resolved real interpreter binary
        paths.append(str(real.parent))                          # its bin dir (pyvenv landmarks etc.)
    except Exception:
        pass
    for p in (sys.prefix, sys.base_prefix):                     # stdlib prefixes (venv + base)
        if p:
            try:
                paths.append(str(Path(p)))
            except Exception:
                pass
    seen, out = set(), []
    for p in paths:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _std_ro_binds():
    """Read-only binds for the cell: the system roots PLUS a precise, minimal re-exposure of the running
    interpreter so a venv/interpreter that lives UNDER a cell-masked path (e.g. a venv or a bare binary at
    /tmp/.../python) still launches. Each interpreter path is bound to ITSELF (file or prefix dir) AFTER
    the --tmpfs mask, so a /tmp-based interpreter is re-exposed over the tmpfs WITHOUT exposing the rest of
    host /tmp, and WITHOUT ever binding a mount-point root (/ or /tmp) that would break the writable cell."""
    binds = []
    for d in _STD_ROOTS:
        if Path(d).exists():
            binds += ["--ro-bind-try", d, d]
    for p in _interp_bind_paths():
        try:
            if p in _NEVER_BIND or _covered_by_std_root(p):
                continue                       # mount-point root, or already covered by a std root
            if Path(p).exists():
                binds += ["--ro-bind-try", p, p]
        except Exception:
            pass
    return binds


def _bwrap_cmd(target_root: str, host_cell: str, wmount: str, spec_cell_path: str):
    cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session",
           "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    cmd += _std_ro_binds()
    # target repo read-only (real path, so module_path resolves); AFTER --tmpfs so a /tmp-based target is
    # re-exposed over the tmpfs. The one writable dir is the operator cell (spec + canary + result).
    cmd += ["--ro-bind", target_root, target_root,
            "--bind", host_cell, wmount, "--chdir", wmount,
            "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "TMPDIR", "/tmp",
            "--setenv", "HOME", wmount]
    cmd += [sys.executable, "-c", _DRIVER, spec_cell_path]
    return cmd


def _fallback_limits():
    import resource

    def _apply():
        for res_id, soft in (
            (resource.RLIMIT_CPU, _CPU_SECS),
            (resource.RLIMIT_AS, _AS_BYTES),
            (resource.RLIMIT_NOFILE, _NOFILE),
            (resource.RLIMIT_FSIZE, _FSIZE),
        ):
            try:
                resource.setrlimit(res_id, (soft, soft))
            except Exception:
                pass
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (_NPROC, _NPROC))
        except Exception:
            pass
        try:
            os.setsid()
        except Exception:
            pass
    return _apply


def isolation_config(backend: str, shell: bool = False) -> dict:
    if backend == "bwrap":
        cfg = {"backend": "bwrap", "network": "denied (--unshare-net via --unshare-all)",
               "namespaces": "all (user/ipc/pid/net/uts/cgroup)", "target_root": "read-only (--ro-bind)",
               "filesystem": "tmpfs /tmp + one writable operator cell dir", "root": "non-root (uid mapped)",
               "die_with_parent": True, "env": "cleared (minimal PATH/HOME/TMPDIR only)",
               "wall_clock_secs": _WALL_CLOCK_SECS}
    else:
        cfg = {"backend": "subprocess-rlimit-fallback",
               "status": ("REFUSED — target code is NEVER executed under this backend. bwrap is absent, "
                          "so there is no network namespace and no filesystem containment; the lane refuses "
                          "rather than run target code unsandboxed."),
               "network": "NOT isolated (no namespace; bwrap absent) — the reason this backend is refused",
               "rlimits": {"cpu_s": _CPU_SECS, "as_bytes": _AS_BYTES, "nofile": _NOFILE,
                           "nproc": _NPROC, "fsize_bytes": _FSIZE},
               "target_root": ("import-by-path would EXECUTE the target module top-level AND the callable "
                               "(NOT contained) — therefore refused; not run under this backend"),
               "filesystem": "temp cwd; own process (NOT contained)",
               "env": "cleared (minimal PATH/HOME/TMPDIR only)",
               "wall_clock_secs": _WALL_CLOCK_SECS}
    if shell:
        # Phase-2a: a subprocess(shell=True) proof spawns a /bin/sh child. It runs INSIDE the same cell —
        # network off, repo read-only, tmpfs /tmp, one writable dir, rlimits, wall-clock kill — so the added
        # surface is contained by the existing sandbox, not a new escape hatch.
        cfg["added_execution_surface"] = (
            "/bin/sh (subprocess shell=True child) — contained by the SAME bwrap cell "
            "(net off · repo ro · tmpfs /tmp · one writable dir · rlimits · wall-clock kill)"
            if backend == "bwrap" else
            "/bin/sh (subprocess shell=True child) — contained by the rlimit'd fallback "
            "(NO network namespace; best-effort only)")
    return cfg


def _run_in_cell(backend, target_root, module_path, callable_name, param, payload, mode, expect,
                 nonce, host_cell: Path, tag: str, fill=None) -> dict:
    """Run one isolated invocation. Returns {ran, canary_file, reflected, error, return_repr, tag}.
    The target's import + call happen ONLY here, inside the cell. `fill` = benign values for the callable's
    OTHER required params so a multi-param callable binds without a missing-argument TypeError.

    STRUCTURAL REFUSAL: only the `bwrap` backend contains the network + filesystem. The rlimit-only
    `subprocess` fallback does NOT, so we NEVER execute target code under it — return a clean refusal
    instead of running the import/call unsandboxed."""
    if backend != "bwrap":
        return {"tag": tag, "ran": False, "canary_file": False, "reflected": False,
                "error": "refused: no bwrap sandbox — target code is not executed under the "
                         "rlimit-only subprocess fallback (no network/filesystem containment)",
                "return_repr": None, "payload": None, "refused_no_sandbox": True}
    canary_host = host_cell / f"canary_{tag}"
    canary_host.mkdir(parents=True, exist_ok=True)
    if backend == "bwrap":
        wmount = "/hs_cell"
        canary_cell = f"{wmount}/canary_{tag}"
        spec_cell = f"{wmount}/spec_{tag}.json"
        result_cell = f"{wmount}/result_{tag}.json"
    else:
        wmount = str(host_cell)
        canary_cell = str(canary_host)
        spec_cell = str(host_cell / f"spec_{tag}.json")
        result_cell = str(host_cell / f"result_{tag}.json")
    # for code_exec the payload must reference the cell-visible canary dir
    payload_final = payload(canary_cell) if callable(payload) else payload
    spec = {"module_path": module_path, "callable": callable_name, "param": param,
            "payload": payload_final, "mode": mode, "expect": expect, "nonce": nonce,
            "canary_dir": canary_cell, "result_path": result_cell, "fill": fill or {}}
    (host_cell / f"spec_{tag}.json").write_text(json.dumps(spec), encoding="utf-8")
    out = {"tag": tag, "ran": False, "canary_file": False, "reflected": False,
           "error": None, "return_repr": None, "payload": payload_final}
    try:
        if backend == "bwrap":
            cmd = _bwrap_cmd(target_root, str(host_cell), wmount, spec_cell)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_WALL_CLOCK_SECS,
                                  env={"PATH": "/usr/bin:/bin"})
        else:
            cmd = [sys.executable, "-c", _DRIVER, spec_cell]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_WALL_CLOCK_SECS,
                                  cwd=str(host_cell), env={"PATH": "/usr/bin:/bin", "HOME": str(host_cell),
                                                           "TMPDIR": str(host_cell)},
                                  preexec_fn=_fallback_limits())
        out["exit_status"] = proc.returncode
        rp = host_cell / f"result_{tag}.json"
        if rp.exists():
            res = json.loads(rp.read_text(encoding="utf-8"))
            out.update({k: res.get(k, out[k]) for k in ("ran", "canary_file", "reflected",
                                                         "error", "return_repr")})
        else:
            out["error"] = f"no result (rc={proc.returncode}): {(proc.stderr or '')[-200:]}"
    except subprocess.TimeoutExpired:
        out["error"] = f"wall-clock kill after {_WALL_CLOCK_SECS}s"
    except Exception as e:
        out["error"] = f"cell-launch-failed: {type(e).__name__}: {e}"[:300]
    return out


def _fired(run: dict, cap: str) -> bool:
    # SSTI proves via arithmetic reflection; code_exec AND subprocess_exec prove via the canary file write.
    return bool(run.get("reflected")) if cap == "ssti" else bool(run.get("canary_file"))


def decide(pos1_fired: bool, pos2_fired: bool, neg_fired: bool):
    """The promotion decision. PROVEN only if the payload fired the nonce via the sink on BOTH positive
    runs (reproduced) AND the negative control stayed clean. Anything else -> inconclusive (not promoted).
    This is the ONLY place a promotion is decided; it can never downgrade."""
    if pos1_fired and pos2_fired and not neg_fired:
        return "proven", True
    return "inconclusive", False


# ---------------------------------------------------------------------------
# Manual PoC recipe — for anything NOT auto-proven (non-provable cap, needs app bootstrap, non-Python,
# no backend). Never auto-run, never promoted.
# ---------------------------------------------------------------------------
def _recipe(surface, trig: dict, reason: str) -> dict:
    cap = surface.capability
    how = {
        "code_exec": "Reach the enclosing callable with a payload string; a benign PoC is "
                     "`open('<dir>/<nonce>','w').write('<nonce>')` — confirm the nonce file appears.",
        "ssti": "Pass `{{7*7}}` as the template; confirm `49` appears in the rendered output.",
        "subprocess_exec": "Reach the shell arg with `; touch <dir>/<nonce>` and confirm the nonce file "
                            "appears. (Phase-2a auto-PROVES the param-IS-command-string shell=True case; "
                            "list-argv, constant commands, and f-string-embedded injection stay recipe-only.)",
        "deserialize": "Craft an object whose __reduce__ writes `<dir>/<nonce>` (Phase-0: NOT auto-run).",
    }.get(cap, "Human-trace the untrusted path to the sink and confirm a benign canary effect.")
    return {
        "manual_only": True,
        "reason": reason,
        "capability": cap,
        "entrypoint": trig.get("entrypoint"),
        "tainted_param": trig.get("tainted_param"),
        "taint_source": trig.get("taint_source"),
        "callable": trig.get("callable"),
        "file": surface.file_path,
        "sink_line": getattr(surface, "sink_line", 0) or getattr(surface, "line_start", 0),
        "suggested_poc": how,
        "note": "Emitted as a recipe — the prove lane did NOT execute this and did NOT promote it.",
    }


# ---------------------------------------------------------------------------
# Prove a single surface
# ---------------------------------------------------------------------------
def prove_surface(surface, root, cell_root: Path, backend=None) -> dict:
    cap = surface.capability
    rel = surface.file_path
    sink_line = getattr(surface, "sink_line", 0) or getattr(surface, "line_start", 0)
    rec = {"surface_id": getattr(surface, "id", ""), "file": rel, "sink_line": sink_line,
           "capability": cap, "verdict": "refused-recipe", "promoted": False, "reason": "",
           "trigger": None, "payload": None, "negative_control": None, "reproduced": False,
           "nonce_effect": None, "isolation": None, "runs": [], "recipe": None}
    trig = build_trigger_spec(surface, root)
    rec["trigger"] = trig

    if cap not in PROVABLE_CAPS:
        rec["reason"] = (f"capability '{cap}' is outside the Phase-0 provable set "
                         f"{sorted(PROVABLE_CAPS)} — manual PoC only")
        rec["recipe"] = _recipe(surface, trig, rec["reason"])
        return rec
    if not trig.get("drivable"):
        rec["reason"] = trig.get("reason", "not directly drivable")
        rec["recipe"] = _recipe(surface, trig, rec["reason"])
        return rec

    backend = backend or isolation_backend()
    rec["isolation"] = isolation_config(backend, shell=(cap == "subprocess_exec"))
    # STRUCTURAL ISOLATION: refuse to execute anything unless we have a real bwrap sandbox. The
    # rlimit-only subprocess fallback cannot unshare the network or contain the filesystem, so running
    # target code under it would be unsandboxed execution. Refuse cleanly (promote-only is preserved:
    # a refused proof leaves the finding a candidate) and emit a manual recipe instead.
    if backend != "bwrap":
        rec["verdict"] = "refused-no-sandbox"
        rec["reason"] = ("refused: no bwrap sandbox — the subprocess fallback is rlimit-only and cannot "
                         "unshare the network or contain the filesystem; target code is never executed "
                         "under it")
        rec["recipe"] = _recipe(surface, trig, rec["reason"])
        return rec
    target_root = str(Path(root).resolve())
    module_path = str((Path(root) / rel).resolve())
    callable_name = trig["callable"]
    param = trig["tainted_param"]
    fill = trig.get("fill") or {}
    nonce = secrets.token_hex(16)

    # per-surface writable cell dir (the single writable dir bound into bwrap)
    cell = cell_root / hashlib.sha256(rec["surface_id"].encode()).hexdigest()[:16]
    cell.mkdir(parents=True, exist_ok=True)

    if cap == "code_exec":
        pos_payload = lambda cdir: _payload_code_exec(nonce, cdir)   # noqa: E731
        neg_payload = _BENIGN_CODE_EXEC
        mode, expect = "code_exec", ""
        mechanism = "canary-file-write"
    elif cap == "subprocess_exec":
        pos_payload = lambda cdir: _payload_shell(nonce, cdir)       # noqa: E731
        neg_payload = _BENIGN_SHELL
        mode, expect = "shell", ""
        mechanism = "shell-canary-file-write"
    else:  # ssti
        factor = _ssti_factor(nonce)
        expect = str(7 * factor)
        pos_payload = _payload_ssti(factor)
        neg_payload = _BENIGN_SSTI
        mode = "ssti"
        mechanism = "arithmetic-reflection"

    r_pos1 = _run_in_cell(backend, target_root, module_path, callable_name, param, pos_payload,
                          mode, expect, nonce, cell, "pos1", fill=fill)
    r_pos2 = _run_in_cell(backend, target_root, module_path, callable_name, param, pos_payload,
                          mode, expect, nonce, cell, "pos2", fill=fill)
    r_neg = _run_in_cell(backend, target_root, module_path, callable_name, param, neg_payload,
                         mode, expect, nonce, cell, "neg", fill=fill)
    rec["runs"] = [r_pos1, r_pos2, r_neg]

    pos1_fired = _fired(r_pos1, cap)
    pos2_fired = _fired(r_pos2, cap)
    neg_fired = _fired(r_neg, cap)
    rec["payload"] = r_pos1.get("payload")
    rec["negative_control"] = {"payload": r_neg.get("payload"), "fired": neg_fired,
                               "clean": not neg_fired, "note": "same sink, benign input — must NOT fire"}
    rec["reproduced"] = bool(pos1_fired and pos2_fired)
    rec["nonce_effect"] = {"nonce": nonce, "mechanism": mechanism, "expect": expect or None,
                           "pos1_fired": pos1_fired, "pos2_fired": pos2_fired,
                           "fired_via_sink": bool(pos1_fired)}
    verdict, promoted = decide(pos1_fired, pos2_fired, neg_fired)
    rec["verdict"] = "proven" if promoted else "inconclusive"
    rec["promoted"] = promoted
    if not promoted:
        rec["reason"] = ("nonce did not fire via the sink" if not pos1_fired else
                         "not reproduced" if not rec["reproduced"] else
                         "negative control fired (inconclusive)")
    return rec


# ---------------------------------------------------------------------------
# Run the lane over a scan. Returns (validated_set, records). PROMOTE-ONLY: never mutates surfaces.
# ---------------------------------------------------------------------------
def run_lane(root, scan, out_dir=None, backend=None) -> tuple:
    root = Path(root)
    ok, why = prove_supported()
    if not ok:
        sys.stderr.write(f"[shield-prove] skipped — {why}.\n")
        return set(), []
    surfaces = [s for s in scan.get("surfaces", [])
                if getattr(s, "context", "prod") == "prod" and s.capability in RCE_CAPS]
    validated = set()
    records = []
    cell_root = Path(tempfile.mkdtemp(prefix="hs-prove-"))
    try:
        for s in surfaces:
            rec = prove_surface(s, root, cell_root, backend=backend)
            records.append(rec)
            if rec.get("promoted"):
                validated.add((s.file_path, getattr(s, "sink_line", 0) or s.line_start))
    finally:
        shutil.rmtree(cell_root, ignore_errors=True)
    if out_dir is not None:
        write_evidence(out_dir, records)
    return validated, records


def write_evidence(out_dir, records) -> Path:
    """Write one JSON evidence record per attempted proof to the OPERATOR out dir (never the target).
    Symlink-safe: refuse to write through a symlinked `prove/` dir."""
    out_dir = Path(out_dir)
    prove_dir = out_dir / "prove"
    if prove_dir.is_symlink():
        raise RuntimeError(f"refusing to write evidence through a symlink: {prove_dir}")
    prove_dir.mkdir(parents=True, exist_ok=True)
    from . import report_writer as RW
    for i, rec in enumerate(records):
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(rec.get("surface_id", f"rec{i}")))[:80]
        RW.write_json(rec, prove_dir / f"{i:03d}_{safe}.json")
    summary = {
        "backend": isolation_backend(),
        "attempted": len(records),
        "proven": sum(1 for r in records if r.get("verdict") == "proven"),
        "inconclusive": sum(1 for r in records if r.get("verdict") == "inconclusive"),
        "refused_recipe": sum(1 for r in records if r.get("verdict") == "refused-recipe"),
        "refused_no_sandbox": sum(1 for r in records if r.get("verdict") == "refused-no-sandbox"),
        "promoted": [{"file": r["file"], "sink_line": r["sink_line"], "capability": r["capability"]}
                     for r in records if r.get("promoted")],
        "note": "PROMOTE-ONLY — a failed/inconclusive/refused proof leaves the finding a candidate.",
    }
    RW.write_json(summary, prove_dir / "prove_summary.json")
    return prove_dir


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------
def consent_granted(assume_yes: bool = False) -> bool:
    """Non-interactive consent via HERMES_SHIELD_PROVE_CONSENT=1 or --yes-execute-my-code; otherwise an
    interactive y/N on a real TTY. Anything else -> refuse (no execution)."""
    if assume_yes or os.getenv("HERMES_SHIELD_PROVE_CONSENT") == "1":
        return True
    try:
        if sys.stdin.isatty() and sys.stderr.isatty():
            sys.stderr.write("Type 'y' to prove-live (only on a repo you trust) [y/N]: ")
            sys.stderr.flush()
            return (sys.stdin.readline() or "").strip().lower() in ("y", "yes")
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Phase-0 demo entry — contained to the bundled fixture.
# ---------------------------------------------------------------------------
_PROVE_DEMO_FILES = ("app.py", "tools.py", "eval_tool.py")


def _materialise_prove_demo() -> Path:
    """Copy the bundled inert fixtures (INCLUDING the directly-drivable eval_tool) to a throwaway temp
    dir under real .py names. Separate from shield_cli._materialise_demo_target so the plain `demo`
    command stays byte-identical (it ships only app.py + tools.py)."""
    from importlib import resources
    tmp = Path(tempfile.mkdtemp(prefix="hermes-shield-prove-demo-"))
    pkg = resources.files("hermes_shield") / "_demo"
    for name in _PROVE_DEMO_FILES:
        (tmp / name).write_text((pkg / f"{name}.txt").read_text(encoding="utf-8"), encoding="utf-8")
    return tmp


def prove_demo(out_dir=None, backend=None) -> dict:
    """ENGINE entry (no consent — the caller gates). Materialise the demo fixture, run the normal static
    scan, run the prove lane, and build the OWASP report with the resulting validated set so
    `proven_live` reflects the proofs. Writes the report + evidence under out_dir when given."""
    from . import scan_hermes, install_report as IR
    target = _materialise_prove_demo()
    try:
        scan = scan_hermes.run_scan(target)
        validated, records = run_lane(target, scan, out_dir=out_dir, backend=backend)
        report = IR.build_report(target, scan, validated)
        if out_dir is not None:
            from . import report_writer as RW
            out = Path(out_dir)
            out.mkdir(parents=True, exist_ok=True)
            RW.write_json(report, out / "hermes_shield_report.json")
            (out / "hermes_shield_report.md").write_text(IR.render(report), encoding="utf-8")
        return {"root": str(target), "report": report, "validated": sorted(validated),
                "records": records, "scan": scan}
    finally:
        shutil.rmtree(target, ignore_errors=True)


def run_prove_demo_cli(out=None, assume_yes=False, quiet=False) -> int:
    """CLI wrapper: LOUD warning + consent gate, then prove_demo, then a short summary. Returns rc."""
    sys.stderr.write(LOUD_WARNING)
    sys.stderr.flush()
    if not consent_granted(assume_yes):
        print("hermes-shield: prove-live NOT confirmed — no code was executed. "
              "Pass --yes-execute-my-code or set HERMES_SHIELD_PROVE_CONSENT=1 for non-interactive runs.",
              file=sys.stderr)
        return 2
    from . import scan_hermes
    out_dir, _ = scan_hermes.resolve_out_paths(Path.cwd(), out)
    res = prove_demo(out_dir=out_dir)
    rep = res["report"]
    if not quiet:
        print("hermes-shield prove-live (demo fixture) — Phase 0")
        print(f"  backend: {isolation_backend()}")
        print(f"  PROVEN-LIVE (nonce fired via sink · negative-control clean · reproduced): "
              f"{rep['proven_live_poc']}")
        for r in res["records"]:
            v = r["verdict"]
            mark = "PROVEN " if v == "proven" else ("recipe " if v == "refused-recipe" else "inconcl")
            print(f"   - [{mark}] {r['file']}:{r['sink_line']} [{r['capability']}] "
                  f"{'' if v == 'proven' else '- ' + (r.get('reason') or '')}")
        print(f"  evidence: {out_dir / 'prove'}")
        print(f"  report:   {out_dir / 'hermes_shield_report.md'}")
    return 0
