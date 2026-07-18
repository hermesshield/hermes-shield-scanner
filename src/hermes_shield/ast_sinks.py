"""
Hermes Shield MVP — AST-backed sink detection (P2.9E).

Detects action sinks from ACTUAL call/write AST nodes, not regex on raw lines. Import lines, def
lines, plain references, comments and string literals are structurally excluded (they are not Call
nodes). String-embedded SQL/paths become STATIC_ARTEFACT_EVIDENCE, never a live sink unless tied to a
real call (open(...,'w'), execute(sql), write_text, shutil.copy, subprocess.run, requests.post, …).

Static only — never imports/executes target code, never reads secrets. Returns sink dicts consumed by
repo_scanner to build ActionSurface records.
"""
from __future__ import annotations
import ast
from typing import List, Optional

# bare method/function name -> (capability, mutating)
_NAME_SINKS = {
    "create_tweet": ("post", True), "post_tweet": ("post", True), "publish_thread": ("post", True),
    "update_status": ("post", True), "media_upload": ("post", True),
    "post_reply": ("reply", True), "reply_to_tweet": ("reply", True),
    "retweet": ("retweet", True), "quote_tweet": ("retweet", True),
    "create_favorite": ("like", True), "like_tweet": ("like", True),
    "send_direct_message": ("dm", True),
    "sendmail": ("email_send", True), "send_email": ("email_send", True),
    "send_draft": ("email_send", True), "create_draft": ("email_send", True),
    # S8.63 SSTI (server-side template injection -> RCE): render_template_string is distinctive to Flask;
    # an attacker-controlled TEMPLATE string renders as code. (from_string handled in _classify_call w/ a hint.)
    "render_template_string": ("ssti", True),
    # S8.58 FP fix: 'system' removed as a BARE name-sink — it false-fired on any .system() method
    # (self.prompt.system(), logger.system()). Real os.system is caught by _DOTTED_SINKS ('os.system') and by
    # the resolved-import path (from os import system -> resolves to os.system), so nothing real is lost.
    # S1.5f-REVIEW (red-team): high-severity SDK families that were silently missed. Distinctive names.
    "put_object": ("cloud_write", True), "delete_object": ("cloud_write", True),
    "upload_file": ("cloud_write", True), "upload_from_string": ("cloud_write", True),
    "upload_blob": ("cloud_write", True), "copy_object": ("cloud_write", True),
    "send_transaction": ("blockchain_tx", True), "sendRawTransaction": ("blockchain_tx", True),
    "chat_postMessage": ("messaging", True), "extractall": ("file_write", True),
    "insert_one": ("db_mutation", True), "insert_many": ("db_mutation", True),
    "delete_one": ("db_mutation", True), "delete_many": ("db_mutation", True),
    "update_one": ("db_mutation", True), "update_many": ("db_mutation", True),
    "bulk_write": ("db_mutation", True), "find_one_and_update": ("db_mutation", True),
}
# deserialisation RCE sinks (dotted, distinctive — bare load/loads is json and stays out). DISCOVERY-
# TEAM additions: the ML supply-chain RCE family (torch/joblib/pandas/numpy/shelve) — agents load
# downloaded checkpoints/dataframes constantly; all are pickle-backed arbitrary code execution.
_DESERIALIZE = {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "dill.load", "dill.loads",
                "cloudpickle.load", "cloudpickle.loads", "jsonpickle.decode",
                "yaml.load", "yaml.unsafe_load", "yaml.full_load",
                "torch.load", "joblib.load", "pandas.read_pickle", "pd.read_pickle", "numpy.load",
                "np.load", "shelve.open"}
# P5 additions (discovery corpus): XXE parsers, clipboard/DNS exfil channels, distinctive instance-
# producing methods, LangChain tool-class suffixes.
_XXE_DOTTED = {"etree.parse", "etree.fromstring", "lxml.etree.parse", "ElementTree.parse", "minidom.parse"}
_EXFIL_DOTTED = {"pyperclip.copy", "clipboard.copy"}
_INST_METHODS = {"open_sftp": "paramiko"}          # var = ssh.open_sftp() -> var is a paramiko instance
_TOOL_CLASS_SUFFIX = ("Tool", "REPL", "Executor", "Agent", "Chain")  # repl = PythonREPLTool() -> tool

# S2.0 STRUCTURAL FAMILY rules — match MODULE-family + VERB-family so every sibling fires (torch.load AND
# torch.jit.load AND keras.load_model), replacing enumerated name allowlists that overfit. Generalises.
_DESERIAL_MODULES = {"pickle", "_pickle", "cpickle", "dill", "marshal", "cloudpickle", "jsonpickle",
                     "yaml", "ruamel", "torch", "joblib", "numpy", "np", "pandas", "pd", "keras",
                     "mlflow", "transformers", "skops", "hickle", "shelve",
                     # S2.1 broadened (blind-pentest misses): more object-deserialisers
                     "fickling", "srsly", "msgpack", "cbor2", "cbor", "phpserialize", "bson"}
_DESERIAL_VERBS = {"load", "loads", "load_model", "read_pickle", "Unpickler", "unpack", "unpackb",
                   "MergeFromString"}
# a construction-hook kwarg is a strong deserialisation signal regardless of module (object_hook etc)
_DESERIAL_HOOK_KWARGS = {"object_hook", "object_pairs_hook", "ext_hook"}
# per-module dangerous verb sets (avoids e.g. asyncio.run — an event loop, not a subprocess — false-firing)
_SUBPROC_FAMILY = {
    "subprocess": {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"},
    "asyncio": {"create_subprocess_shell", "create_subprocess_exec"},
    "os": {"spawnv", "spawnve", "spawnl", "spawnlp", "spawnvp", "posix_spawn", "posix_spawnp", "spawn"},
    "runpy": {"run_path", "run_module"},
    "pexpect": {"spawn", "run"},
    "commands": {"getoutput", "getstatusoutput"},
}
# library-aware: dotted-chain ROOT -> capability. A call on an object from these SDKs is a sink
# regardless of method name (the danger is the LIBRARY, not the verb) — CTO-review #1.
_DANGER_LIBS = {
    "stripe": "payment", "web3": "blockchain_tx", "w3": "blockchain_tx", "boto3": "cloud_write",
    "paramiko": "subprocess_exec", "fabric": "subprocess_exec", "telethon": "messaging",
    "twilio": "messaging", "sendgrid": "email_send", "smtplib": "email_send", "slack_sdk": "messaging",
    # S1.9 remote-exec / transfer / remote-DB libraries (discovery-team gaps)
    "docker": "subprocess_exec", "kubernetes": "subprocess_exec", "asyncssh": "subprocess_exec",
    "celery": "subprocess_exec", "ftplib": "external_write", "telnetlib": "subprocess_exec",
    "xmlrpc": "external_write", "redis": "db_mutation", "pymongo": "db_mutation",
    "neo4j": "db_mutation", "elasticsearch": "db_mutation", "ldap3": "db_mutation",
    # S2.0 held-out families: shell-runner + file-transfer libraries
    "sh": "subprocess_exec", "plumbum": "subprocess_exec", "pexpect": "subprocess_exec",
    "pysftp": "external_write", "scp": "external_write", "smbprotocol": "external_write", "smb": "external_write",
    # S2.0 messaging/queue-publish libraries (a remote send is an action surface)
    "kafka": "messaging", "confluent_kafka": "messaging", "aiokafka": "messaging",
    "pika": "messaging", "websocket": "messaging", "websockets": "messaging", "stomp": "messaging",
    # S2.1 AGENT/LLM frameworks (the entire agent-invocation surface the blind pentest found missing)
    "autogen": "tool_invoke", "haystack": "tool_invoke", "dspy": "tool_invoke", "guidance": "tool_invoke",
    "langgraph": "tool_invoke", "crewai": "tool_invoke", "semantic_kernel": "tool_invoke",
    "llama_index": "tool_invoke", "llamaindex": "tool_invoke", "autogpt": "tool_invoke",
    # S3.0 completeness gap-map (tool-bank additions):
    "mcp": "tool_invoke", "fastmcp": "tool_invoke",                                    # MCP transport
    "langchain": "tool_invoke", "langchain_core": "tool_invoke",                       # canonical framework
    "langchain_community": "tool_invoke", "langchain_experimental": "tool_invoke",
    "e2b": "subprocess_exec", "e2b_code_interpreter": "subprocess_exec",               # remote code sandboxes
    "modal": "subprocess_exec", "riza": "subprocess_exec",
    "smolagents": "tool_invoke", "taskweaver": "tool_invoke", "superagi": "tool_invoke",  # code-exec agents
    "babyagi": "tool_invoke", "phidata": "tool_invoke", "agno": "tool_invoke",
    "letta": "tool_invoke", "memgpt": "tool_invoke", "browser_use": "tool_invoke",
    "pyautogui": "computer_use", "pynput": "computer_use",                             # native computer-use
    "ccxt": "payment",                                                                 # crypto trading
    "discord": "messaging", "resend": "email_send", "aiosmtplib": "email_send", "nio": "messaging",
    "chromadb": "db_mutation", "qdrant_client": "db_mutation", "lancedb": "db_mutation",  # vector-store writes
    "pymilvus": "db_mutation", "weaviate": "db_mutation",
    "ansible_runner": "subprocess_exec", "pulumi": "subprocess_exec", "python_terraform": "subprocess_exec",
    "ctypes": "code_exec", "cffi": "code_exec",                                         # native code load
}
# S3.0 distinctive bare-method sinks (fire regardless of receiver; low collision)
_EXTRA_NAME_SINKS = {
    "call_tool": "tool_invoke", "run_code": "code_exec",                # MCP / e2b
    "execute_script": "code_exec", "execute_async_script": "code_exec",  # selenium arbitrary JS
    "run_cell": "code_exec", "compile_restricted": "code_exec",          # IPython / RestrictedPython
    # S8.36 agent-specific code-exec primitives (found by the CVE benchmark - LangChain PALChain CVE-2023-44467
    # executes LLM code via PythonREPL). These framework classes run arbitrary code; a bare exec/eval check misses them.
    "PythonREPL": "code_exec", "PythonREPLTool": "code_exec", "PythonAstREPLTool": "code_exec",
    "PythonAstREPLTool": "code_exec", "PALChain": "code_exec",
}
# S8 COMPOUNDING: distinctive sink names the AI finder confirmed on past repos, absorbed as free static
# rules. Loaded at import; reload_learned() re-reads after the autoresearch loop absorbs new ones.
from . import learned_sinks as _learned_sinks
_LEARNED_SINKS = _learned_sinks.learned_name_sinks()
_LEARNED_STRUCTURAL = _learned_sinks.structural_rules()


def reload_learned():
    """Re-read the learned-sink store (called by the autoresearch loop after it absorbs new sinks)."""
    global _LEARNED_SINKS, _LEARNED_STRUCTURAL
    _LEARNED_SINKS = _learned_sinks.learned_name_sinks()
    _LEARNED_STRUCTURAL = _learned_sinks.structural_rules()


def _match_structural(module_root, verb, guard_ok):
    """Tier C: resolved-module match against cached learned structural rules (never the verb string)."""
    if not module_root:
        return None
    for r in _LEARNED_STRUCTURAL:
        if r["module_root"] != module_root:
            continue
        if r["generality"] == "verb_set" and verb in r["verbs"]:
            return r["capability"]
        if r["generality"] == "module_wide" and guard_ok:
            return r["capability"]
    return None


# read-method prefixes + constructors excluded from library-aware flagging (they are not actions)
_LIB_READ_PREFIX = ("get", "list", "describe", "read", "head", "fetch", "query", "is_", "to_", "load", "retrieve")
_LIB_CTOR = {"client", "resource", "Session", "session", "Connection", "connect", "SSHClient",
             "SMTP", "SMTP_SSL", "Web3", "HTTPProvider", "Client"}
# module.method dotted sinks
_DOTTED_SINKS = {
    "requests.post": ("external_write", True), "requests.put": ("external_write", True),
    "requests.patch": ("external_write", True), "requests.delete": ("external_write", True),
    "httpx.post": ("external_write", True), "httpx.put": ("external_write", True),
    "httpx.patch": ("external_write", True), "httpx.delete": ("external_write", True),
    "requests.get": ("external_read", False), "httpx.get": ("external_read", False),
    "subprocess.run": ("subprocess_exec", True), "subprocess.Popen": ("subprocess_exec", True),
    "subprocess.call": ("subprocess_exec", True), "subprocess.check_call": ("subprocess_exec", True),
    "subprocess.check_output": ("subprocess_exec", True), "os.system": ("subprocess_exec", True),
    "shutil.copy": ("publish_write", True), "shutil.copyfile": ("publish_write", True),
    "shutil.move": ("publish_write", True),
    "shutil.rmtree": ("file_delete", True),
    "os.remove": ("file_delete", True), "os.unlink": ("file_delete", True), "os.rmdir": ("file_delete", True),
    "os.popen": ("subprocess_exec", True), "os.execv": ("subprocess_exec", True),
    "os.execvp": ("subprocess_exec", True), "os.execve": ("subprocess_exec", True),
    "subprocess.getoutput": ("subprocess_exec", True), "pty.spawn": ("subprocess_exec", True),
    "os.chmod": ("file_perms", True), "os.chown": ("file_perms", True),
    "os.rename": ("file_write", True), "os.replace": ("file_write", True),
    "smtplib.SMTP": ("email_send", True),
}
# method names that are browser/CDP actions (attr on any receiver)
_BROWSER_METHODS = {
    "click": ("browser_click", True), "fill": ("browser_type", True),
    "type": ("browser_type", True), "send_keys": ("browser_type", True),
    "press": ("browser_submit", True), "submit": ("browser_submit", True),
    "keyDown": ("computer_use", True),
}
_WRITE_METHODS = {"write_text": True, "write_bytes": True}
_PUBLISH_HINT = ("ready", "approved", "publish", "postable", "outbound", "queue")
_SQL_MUT = ("update ", "insert into", "delete from", "drop table", "truncate", "alter table", "replace into")


def _attr_name(func) -> Optional[str]:
    return func.attr if isinstance(func, ast.Attribute) else (func.id if isinstance(func, ast.Name) else None)


def _dotted(func) -> Optional[str]:
    parts: List[str] = []
    cur = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _chain_str(func) -> str:
    """Flatten a possibly-chained call func into a dotted-ish string incl. intermediate calls."""
    parts: List[str] = []
    cur = func
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        else:
            break
    return ".".join(reversed(parts))


def _first_str_arg(node: ast.Call) -> str:
    for a in node.args:
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            return a.value
    for kw in node.keywords:
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return ""


def _collect_aliases(tree):
    """Intra-module import maps so aliased/renamed sinks resolve to their origin (mutation-test gap).
    sym_alias: local_name -> 'module.origname' (from X import y [as z]); mod_alias: local -> 'module'
    (import X as z)."""
    sym_alias, mod_alias = {}, {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                sym_alias[a.asname or a.name] = f"{n.module}.{a.name}"
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    mod_alias[a.asname] = a.name
    return sym_alias, mod_alias


def _chain_root(node):
    """The Name id at the root of a call/attribute chain, or None."""
    cur = node
    while isinstance(cur, ast.Call):
        cur = cur.func
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else None


def _danger_lib_key(root, mod_alias, inst_map):
    """Resolve a chain-root name to a _DANGER_LIBS key via direct name / module alias / instance map."""
    if root in _DANGER_LIBS:
        return root
    if mod_alias.get(root) in _DANGER_LIBS:
        return mod_alias[root]
    v = inst_map.get(root)                 # instance-map value must itself be a real lib key
    if v in _DANGER_LIBS:                  # (not e.g. the "__tool__" marker, handled by the P3 branch)
        return v
    return None


def _collect_instances(tree, sym_alias, mod_alias):
    """S1.9 KEY FIX: track `var = <danger-lib>....(...)` so a call on the INSTANCE (`sftp.put`,
    `c.run`, `client.containers.run`) resolves to its library, not just the literal lib name. Fixpoint
    handles multi-hop (`ssh = paramiko.SSHClient(); sftp = ssh.open_sftp()`)."""
    inst = {}
    for _ in range(4):
        changed = False
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                var = n.targets[0].id
                if var in inst:
                    continue
                root = _chain_root(n.value)
                # also let a `from fabric import Connection; c = Connection(...)` resolve via sym_alias
                key = _danger_lib_key(root, mod_alias, inst) if root else None
                if not key and root and root in sym_alias:
                    key = _DANGER_LIBS.get(sym_alias[root].split(".")[0]) and sym_alias[root].split(".")[0]
                if not key and isinstance(n.value, ast.Call):
                    cf = n.value.func
                    cname = cf.id if isinstance(cf, ast.Name) else (_attr_name(cf) or "")
                    if cname.endswith(_TOOL_CLASS_SUFFIX):        # repl = PythonREPLTool()
                        key = "__tool__"
                    elif _attr_name(cf) in _INST_METHODS:          # sftp = ssh.open_sftp()
                        key = _INST_METHODS[_attr_name(cf)]
                if key:
                    inst[var] = key
                    changed = True
        if not changed:
            break
    return inst


def _resolve_dotted(func, sym_alias, mod_alias):
    """Map a bare/aliased call back to its imported dotted origin (e.g. `run` -> `subprocess.run`,
    `sp.run` -> `subprocess.run`). Returns None if not resolvable via imports."""
    if isinstance(func, ast.Name):
        return sym_alias.get(func.id)
    d = _dotted(func)
    if d:
        root = d.split(".")[0]
        if root in mod_alias:
            return mod_alias[root] + d[len(root):]
    return None


def _classify_call(node: ast.Call, sym_alias=None, mod_alias=None, inst_map=None):
    """Return (capability, mutating, sink_kind, static_artifact_type) or None if not a sink."""
    func = node.func
    bare = _attr_name(func)
    dotted = _dotted(func)
    chain = _chain_str(func)
    # resolve aliased/renamed imports to their dotted origin, then treat the origin as the identity
    rdotted = _resolve_dotted(func, sym_alias or {}, mod_alias or {})
    # NOTE (S3.1): SSRF (non-constant fetch URL) was reverted here — flagging EVERY variable-URL
    # requests.get was too noisy (16 benign config-driven URLs on ops/) and broke the "requests.get is
    # read-only" core semantics. The correct SSRF is TAINT-GATED (flag only when the URL derives from
    # untrusted input) — deferred to its own dedicated loop. The `ssrf_fetch` capability stays reserved.
    if rdotted:
        if rdotted in _DESERIALIZE:
            return "deserialize", True, "ast_call", None
        if rdotted in _DOTTED_SINKS:
            cap, mut = _DOTTED_SINKS[rdotted]
            return cap, mut, "ast_call", None
        # let a resolved 'subprocess.run'/'requests.post' flow through the normal branches too:
        dotted = dotted or rdotted

    # model/vision: responses.create / chat.completions.create -> vision if an arg mentions an image
    if bare == "create" and ("responses" in chain or "completions" in chain or "messages" == chain.split(".")[0]):
        blob = ""
        for a in ast.walk(node):
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                blob += a.value.lower()
        if any(k in blob for k in ("input_image", "image_url", "vision")):
            return "vision_model_call", False, "ast_call", None
        return "model_call", False, "ast_call", None

    # code execution (BUILTINS — Name calls only, so df.eval / re.compile attr-calls don't false-fire)
    if isinstance(func, ast.Name) and func.id in ("eval", "exec", "compile", "__import__"):
        return "code_exec", True, "ast_call", None
    # deserialisation RCE (dotted, distinctive)
    if dotted in _DESERIALIZE:
        return "deserialize", True, "ast_call", None

    # ---- S2.0 STRUCTURAL FAMILY rules (generalize over siblings, not enumerated names) ----
    # effective root/verb use the RESOLVED import so `from skops.io import load; load(f)` still resolves
    # to (skops, load), not (load, load) — a general mechanism, not per-case memorisation.
    _famroot = (rdotted.split(".")[0] if rdotted else (chain.split(".")[0] if chain else ""))
    _famverb = (rdotted.split(".")[-1] if rdotted else bare)
    if _famroot in _DESERIAL_MODULES and _famverb in _DESERIAL_VERBS:   # torch.load / torch.jit.load / keras.load_model
        return "deserialize", True, "ast_call", None
    # object-hook kwarg = deserialisation into arbitrary objects, ANY module (blind-pentest generalisation)
    if _famverb in _DESERIAL_VERBS and any(k.arg in _DESERIAL_HOOK_KWARGS for k in node.keywords):
        return "deserialize", True, "ast_call", None
    # bare-instance call on an agent/LLM-framework object: `program = guidance(...); program(x)`
    if isinstance(func, ast.Name) and (inst_map or {}).get(func.id) in _DANGER_LIBS:
        return _DANGER_LIBS[inst_map[func.id]], "unknown", "ast_lib_aware", None
    if _famverb == "from_pretrained" and any(                  # HF: only dangerous with trust_remote_code=True
            k.arg == "trust_remote_code" and isinstance(k.value, ast.Constant) and k.value.value for k in node.keywords):
        return "deserialize", True, "ast_call", None
    if _famroot in _SUBPROC_FAMILY and _famverb in _SUBPROC_FAMILY[_famroot]:  # subprocess/asyncio/os/runpy/pexpect
        return "subprocess_exec", True, "ast_call", None
    if bare == "attrgetter" and node.args and isinstance(node.args[0], ast.Constant) \
            and str(node.args[0].value) in ("system", "popen", "eval", "exec", "spawn", "call"):
        return "dynamic_dispatch", True, "ast_dynamic_dispatch", "DYNAMIC_DISPATCH"  # mirror of methodcaller
    # transfer / upload FAMILY (distinctive verbs) + code-load + sqlalchemy raw exec
    if bare in ("upload_from_filename", "upload_from_file", "files_upload", "storeFile", "storbinary"):
        return "external_write", True, "ast_call", None
    if bare == "exec_driver_sql":
        return "db_mutation", True, "ast_call", None
    if bare == "exec_module":
        return "code_exec", True, "ast_call", None

    # ---- P5 discovery-corpus signatures (novel surfaces) ----
    if dotted in _XXE_DOTTED:                                   # etree.parse(user_xml) -> XXE
        return "deserialize", True, "ast_call", None
    if dotted in _EXFIL_DOTTED:                                 # pyperclip.copy(secret) -> exfil
        return "external_write", True, "ast_call", None
    if dotted in ("socket.gethostbyname", "socket.getaddrinfo") and node.args and not isinstance(node.args[0], ast.Constant):
        return "external_write", True, "ast_call", None        # DNS exfil (non-constant host)
    if bare in ("apply_async", "delay"):                       # celery remote task dispatch
        return "tool_invoke", True, "ast_call", None
    # S8.63 SSTI: env.from_string(<template>) — a Jinja Environment compiling an attacker-controlled template
    # string is RCE. Hint-gated on the receiver so a generic .from_string() does not false-fire.
    if bare == "from_string" and any(h in chain.lower() for h in ("env", "jinja", "template", "tmpl")):
        return "ssti", True, "ast_call", None
    if bare in ("render", "generate", "stream") and isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call):
        vn = _attr_name(func.value.func) or (func.value.func.id if isinstance(func.value.func, ast.Name) else "")
        if vn in ("Template", "from_string", "Environment", "get_template", "compile_template", "PageTemplate"):
            return "code_exec", True, "ast_call", None          # template-engine SSTI family -> RCE
    if dotted in ("dns.resolver.resolve", "resolver.resolve", "dns.resolver.query") and node.args \
            and not isinstance(node.args[0], ast.Constant):
        return "external_write", True, "ast_call", None          # DNS exfil (non-constant host)
    if bare == "kickoff":                                         # crewai crew.kickoff() -> agent run
        return "tool_invoke", True, "ast_call", None
    if bare in _EXTRA_NAME_SINKS:                                 # S3.0 distinctive sinks (call_tool/run_code/...)
        return _EXTRA_NAME_SINKS[bare], True, "ast_call", None
    if bare in _LEARNED_SINKS:                                    # S8 compounding: AI-found, absorbed as static
        return _LEARNED_SINKS[bare], True, "ast_call_learned", None
    if bare in ("add", "upsert", "save_context", "remember", "remember_many", "add_texts", "add_documents") \
            and any(k in chain for k in ("memory", "vector", "store", "index", "embed")):
        return "db_mutation", True, "ast_call", None            # agent memory / vector-store write
    # S3.5 (absorbed from the AI tier, per adjudicator): dynamic import of a NON-CONSTANT module/class
    # string (config/serialized/LLM-driven) = code-load review. Constant import stays out (framework use).
    if bare == "import_module" and node.args and not isinstance(node.args[0], ast.Constant):
        return "dynamic_dispatch", True, "ast_dynamic_dispatch", "DYNAMIC_DISPATCH"
    if bare == "YAML":                                          # ruamel YAML(typ='unsafe')
        for kw in node.keywords:
            if kw.arg == "typ" and isinstance(kw.value, ast.Constant) and "unsafe" in str(kw.value.value):
                return "deserialize", True, "ast_call", None
    if bare == "methodcaller" and node.args and isinstance(node.args[0], ast.Constant) \
            and str(node.args[0].value) in ("system", "popen", "eval", "exec", "spawn", "call"):
        return "dynamic_dispatch", True, "ast_dynamic_dispatch", "DYNAMIC_DISPATCH"
    if bare == "partial" and node.args:
        a0 = node.args[0]
        a0d = _dotted(a0) if isinstance(a0, ast.Attribute) else (a0.id if isinstance(a0, ast.Name) else "")
        if a0d in ("os.system", "os.popen", "eval", "exec", "subprocess.run", "subprocess.call", "subprocess.Popen"):
            return "dynamic_dispatch", True, "ast_dynamic_dispatch", "DYNAMIC_DISPATCH"
    # library-aware: a call on an object rooted in a known-dangerous SDK is a sink regardless of the
    # method name (the danger is the LIBRARY, not the verb) — CTO-review #1. Root of the dotted chain.
    # SKEPTIC FP FIX: exclude read-PREFIXES (get_balance/retrieve/list_*) and CONSTRUCTORS (client/
    # SSHClient/SMTP) — they are not actions. (Residual: a local var named w3/stripe can still collide;
    # import-gating is a follow-up.)
    _root = chain.split(".")[0] if chain else ""
    _lib = _danger_lib_key(_root, mod_alias or {}, inst_map or {})   # resolves via import + INSTANCE map
    # skip reads (get/list/...), named constructors, AND Capitalised methods (redis.Redis()/SSHClient()
    # /Connection() are CLIENT CONSTRUCTORS, not actions) + common factory names.
    _guard_ok = bool(bare and not bare.startswith(_LIB_READ_PREFIX) and bare not in _LIB_CTOR
                     and not (bare and bare[0].isupper()) and bare not in ("from_env", "driver", "connect"))
    if (_lib and _guard_ok):
        return _DANGER_LIBS[_lib], "unknown", "ast_lib_aware", None
    # S8 Tier C: learned STRUCTURAL rules — match the RESOLVED module root (via imports), never the verb
    # string. So a learned subprocess rule catches sp.run_shell(x) but foo.check_call() on a local foo does not.
    if _root and _LEARNED_STRUCTURAL:
        _mroot = (mod_alias or {}).get(_root, _root)
        _scap = _match_structural(_mroot, bare, _guard_ok)
        if _scap:
            return _scap, True, "ast_call_structural", None
    # stripe / payment .create
    if bare == "create" and "stripe" in chain.lower():
        return "payment", True, "ast_call", None
    # langchain/agent tool .run ; selenium driver .get ; pyppeteer page .evaluate
    cl = chain.lower()
    if bare == "run" and any(r in cl for r in ("repl", "python_repl")):    # S8.36 repl.run(code) = code exec
        return "code_exec", True, "ast_call", None
    if bare == "run" and any(r in cl for r in ("tool", "agent", "chain")):
        return "tool_invoke", True, "ast_call", None
    if bare == "get" and any(r in cl for r in ("driver", "browser")):
        return "browser_submit", True, "ast_call", None
    if bare == "evaluate" and "page" in cl:
        # FP2 (scoped to browser page.evaluate ONLY — never to the eval/exec builtin branch): a CONSTANT JS
        # body with an untrusted ARGUMENT is not code injection. Fire only when the code STRING is non-constant
        # (interpolated), or when a constant body itself evals its arg. This never touches eval()/exec().
        code_arg = node.args[0] if node.args else None
        _const_safe = (isinstance(code_arg, ast.Constant) and isinstance(code_arg.value, str)
                       and not any(t in code_arg.value for t in ("eval(", "new Function", "Function(",
                                                                  "setTimeout(", "setInterval(", "import(")))
        if code_arg is not None and not _const_safe:
            return "code_exec", True, "ast_call", None
        # constant/absent JS body -> not a code_exec surface; fall through

    # telegram send — often shipped via a subprocess/CLI or an api.telegram.org request rather than a
    # bot.send_message() call. Detect by marker strings in the call args (P2.9F-REVIEW census fix).
    if (dotted in ("subprocess.run", "subprocess.Popen", "subprocess.call", "os.system")
            or bare in ("run", "Popen", "call", "system", "post")):
        blob = ""
        for a in ast.walk(node):
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                blob += a.value.lower()
        if "api.telegram.org" in blob or "sendmessage" in blob or (
                "hermes" in blob and "send" in blob) or "tg_send" in blob:
            return "telegram_send", True, "ast_call", None

    # HTTP client-INSTANCE calls: session.post / client.put / self.api.post(url, json=...) — these are
    # not literally requests.post so the dotted map misses them (a big real recall gap). Gate on HTTP
    # signals (http kwargs / url-ish first arg / http-ish receiver) to keep precision.
    if bare in ("post", "put", "patch", "delete", "request") and isinstance(func, ast.Attribute):
        kws = {k.arg for k in node.keywords}
        http_kw = bool(kws & {"json", "data", "headers", "params", "auth", "cookies", "files"})
        a0 = node.args[0] if node.args else None
        url_arg = isinstance(a0, ast.Constant) and isinstance(a0.value, str) and a0.value[:5].lower().startswith(("http", "/", "ws"))
        # SKEPTIC FP FIX: dropped the receiver-name signal — session/client/conn collide with SQLAlchemy
        # `session.delete(obj)`, redis `client.delete(k)`, DB `conn.delete(row)` (all NOT http writes).
        if http_kw or url_arg:
            return "external_write", True, "ast_call", None
    if bare == "urlopen":  # SKEPTIC FP FIX: urlopen is a READ unless it carries data/POST (it was the
        has_data = len(node.args) >= 2 or any(k.arg == "data" for k in node.keywords)  # #1 false-positive
        if has_data:
            return "external_write", True, "ast_call", None
        return "external_read", False, "ast_call", None
    # Path.unlink() / Path.rmdir() are distinctive file deletes. NOT bare `.remove` — that is usually
    # list.remove()/set.remove() (precision fix); real os.remove is caught via the dotted map above.
    if bare in ("unlink", "rmdir") and isinstance(func, ast.Attribute):
        return "file_delete", True, "ast_call", None

    # dotted module.method (requests.post, subprocess.run, os.system, shutil.copy)
    if dotted and dotted in _DOTTED_SINKS:
        cap, mut = _DOTTED_SINKS[dotted]
        return cap, mut, "ast_call", None
    # os.system when bare via alias
    if dotted == "os.system":
        return "subprocess_exec", True, "ast_call", None

    # chained email: <...>.messages().send  or  .messages().send(...).execute()
    if "messages" in chain and "send" in chain:
        return "email_send", True, "ast_chained_call", None

    # bare name sinks (create_tweet, update_status, send_email, ...)
    if bare in _NAME_SINKS:
        cap, mut = _NAME_SINKS[bare]
        return cap, mut, "ast_call", None

    # Path.write_text / write_bytes
    if bare in _WRITE_METHODS:
        arg = _chain_str(func)
        cap = "publish_write" if any(h in arg.lower() for h in _PUBLISH_HINT) else "file_write"
        return cap, True, "ast_write", None

    # open(path, "w"/"a"/...) AND Path.open("w"/"a") — DOGFOOD FIX (found in hermes_shield_growth):
    # builtin open(file, mode) has mode at arg[1]; pathlib Path.open(mode) has mode at arg[0]. We only
    # checked arg[1], so every `path_obj.open("a")` append-write was silently missed.
    if bare == "open":
        idx = 0 if isinstance(func, ast.Attribute) else 1   # method .open() -> mode is first arg
        cand = None
        if len(node.args) > idx and isinstance(node.args[idx], ast.Constant) and isinstance(node.args[idx].value, str):
            cand = node.args[idx].value
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                cand = str(kw.value.value)
        # only a real file MODE (short, mode-chars) — avoids obj.open("some/path") false positives
        mode = cand if (cand and len(cand) <= 4 and all(c in "rwaxbt+U" for c in cand)) else ""
        if any(w in mode for w in ("w", "a", "x")):
            hint_src = (_first_str_arg(node) + " " + chain).lower()
            cap = "publish_write" if any(h in hint_src for h in _PUBLISH_HINT) else "file_write"
            return cap, True, "ast_write", None
        return None  # read mode

    # SQL execute(...) — red-team INVERSION fix: a CONSTANT SELECT is safe (read), a CONSTANT mutation
    # is a sink, and a NON-CONSTANT arg (f-string / concat / variable) is the SQL-injection-prone /
    # dynamic form and must be flagged, not dropped.
    if bare in ("execute", "executemany", "executescript"):   # +executescript (runs multiple stmts)
        a0 = node.args[0] if node.args else None
        if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
            sql = a0.value.lower()
            if any(k in sql for k in _SQL_MUT):
                return ("queue_mutation" if "x_post_queue" in sql else "db_mutation"), True, "ast_call", None
            return None  # constant SELECT = read
        # SKEPTIC FP FIX: non-constant SQL is often a parameterised SELECT (a read), not a mutation.
        # Emit a distinct NON-critical review capability, not 'db_mutation'.
        if a0 is not None:
            return "dynamic_sql_review", "unknown", "ast_dynamic_sql", None
        return None

    # SKEPTIC FP FIX: press("Escape"/"Control+A") is NOT a form submit — only Enter/Return/Tab is.
    if bare == "press" and isinstance(func, ast.Attribute):
        a0 = _first_str_arg(node)
        return ("browser_submit" if a0 in ("Enter", "Return", "Tab") else "browser_type"), True, "ast_call", None
    # browser/CDP method calls (attr on any receiver): click/fill/type/submit
    if isinstance(func, ast.Attribute) and bare in _BROWSER_METHODS:
        cap, mut = _BROWSER_METHODS[bare]
        return cap, mut, "ast_call", None

    # telegram send
    if bare in ("send_message",) and "bot" in chain.lower():
        return "telegram_send", True, "ast_call", None

    # .save(path) — img.save / workbook.save / model.save-to-file writes a file (DOGFOOD: art scripts
    # missed). Gate on a POSITIONAL arg: a no-arg / keyword-only .save() is usually an ORM save and is
    # too ambiguous to flag without flooding, so it naturally falls through.
    if bare == "save" and isinstance(func, ast.Attribute) and node.args:
        return "file_write", True, "ast_call", None

    # P4 DYNAMIC DISPATCH — the callee is chosen at RUNTIME (undecidable statically). Surface it for
    # REVIEW instead of leaving it totally silent (discovery-team gap: TOOLS[name](), HANDLERS[k](),
    # getattr(os,x)(), available_functions[fn]()). Honest: flagged, never claimed to be resolved.
    # FP FIX (precision audit): only flag when the callee KEY/ATTR is NON-CONSTANT (attacker-influenceable
    # dispatch). d['const']() and getattr(x,'literal',default)() are benign defensive idioms, not dispatch.
    if isinstance(func, ast.Subscript) and not isinstance(getattr(func, "slice", None), ast.Constant):
        return "dynamic_dispatch", "unknown", "ast_dynamic_dispatch", "DYNAMIC_DISPATCH"
    if (isinstance(func, ast.Call) and isinstance(func.func, ast.Name) and func.func.id == "getattr"
            and len(func.args) >= 2 and not isinstance(func.args[1], ast.Constant)):
        return "dynamic_dispatch", "unknown", "ast_dynamic_dispatch", "DYNAMIC_DISPATCH"

    # P3 agent tool classes: .run/.invoke on a LangChain-style Tool/REPL/Executor/Agent/Chain receiver
    if bare in ("run", "invoke", "arun", "ainvoke") and (
            any(k in chain for k in ("Tool", "REPL", "Executor", "Agent", "Chain"))
            or (inst_map or {}).get(chain.split(".")[0] if chain else "") == "__tool__"):
        return "tool_invoke", True, "ast_call", None

    # COMPLETENESS NET (S1.5f): a METHOD call whose name matches a broad action-verb set but that we
    # could not classify precisely -> surface it as `unknown_action` for HUMAN REVIEW rather than
    # silently dropping it. Catches action-shaped surfaces we've never seen. Method-call only (a bare
    # function of these names is usually a local/util call); reported separately so it never dilutes
    # the high-confidence findings. (Residual: dynamic-dispatch calls are invisible to any static tool.)
    if isinstance(func, ast.Attribute) and bare in _ACTION_VERBS:
        return "unknown_action", "unknown", "ast_unknown_verb", "UNKNOWN_ACTION_VERB"

    return None


# CURATED action-verb set for the completeness net — HIGH-signal, LOW-collision names for external /
# irreversible / high-value actions we may lack a precise signature for. Deliberately NOT broad data-
# structure verbs (update/insert/commit/connect/save/create collide with dict/list/db plumbing and
# produce noise that BURIES real findings). These become "review" items, reported separately.
_ACTION_VERBS = {
    # network / messaging out (socket/pipe collisions accepted — still worth a look)
    "sendall", "sendto", "publish", "broadcast",
    # data movement out
    "upload", "download",
    # money / crypto (high value, rare collision)
    "transfer", "pay", "charge", "withdraw", "checkout", "purchase", "sign_transaction",
    # infrastructure / destructive
    "deploy", "provision", "purge", "wipe", "truncate", "revoke", "teardown", "destroy",
    # browser navigation (SSRF-ish)
    "navigate", "goto", "screenshot", "save_screenshot",
    # agent tool invocation — the modern attack surface
    "invoke", "call_tool", "run_tool", "use_tool", "execute_command", "spawn_process",
}


# FP4: a route is auth-gated when it has a route decorator AND a param default Depends(<curated auth name>).
_AUTH_DEPS = {"current_user", "current_org", "get_current_user", "get_current_org", "current_active_user",
              "get_current_active_user", "authenticated_user", "require_auth", "verify_token", "get_org",
              "get_current_tenant", "api_key_auth"}
_ROUTE_VERBS = ("get", "post", "put", "delete", "patch")
# FP3: destination roots that mean "operator/user config", not attacker content.
_CONFIG_ROOTS = {"self", "cls", "config", "settings", "conf", "env", "os", "org", "current_org", "current_user"}


def _is_auth_gated_route(node) -> bool:
    is_route = any((isinstance(d, ast.Attribute) and d.attr in _ROUTE_VERBS)
                   or (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in _ROUTE_VERBS)
                   for d in getattr(node, "decorator_list", []))
    if not is_route:
        return False
    a = getattr(node, "args", None)
    if not a:
        return False
    for d in list(getattr(a, "defaults", [])) + list(getattr(a, "kw_defaults", [])):
        if isinstance(d, ast.Call):
            fn = d.func
            fname = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
            if fname == "Depends" and d.args:
                a0 = d.args[0]
                tail = a0.attr if isinstance(a0, ast.Attribute) else (a0.id if isinstance(a0, ast.Name) else "")
                if tail in _AUTH_DEPS:
                    return True
    return False


# FP-Fix1: capabilities whose DESTINATION is a distinct argument we can extract and reason about
# separately from the (often-tainted) CONTENT argument. For these a tainted-CONTENT send to a
# fixed/config destination is NOT exfil (see guard_attribution.apply's fixed-destination downgrade).
_DEST_AWARE_CAPS = {"external_write", "telegram_send", "email_send"}


def _unwrap_dest(node):
    """Peel a single str()/int()/format() wrapper around a destination expression (chat_id is often
    stringified: str(os.getenv('CHAT_ID'))). Returns the inner arg node, else the node unchanged."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
            and node.func.id in ("str", "int") and len(node.args) == 1 and not node.keywords:
        return node.args[0]
    return node


def _dest_node(node: ast.Call, cap: str, assigns=None):
    """The AST node of the DESTINATION argument for a fixed-channel / external sink, or None when the
    destination is not a statically-identifiable argument. Capability-aware:
      * external_write: the URL — args[0] or a url/endpoint/uri kwarg (unchanged behaviour);
      * telegram_send: the chat_id — a chat_id= kwarg, the 'chat_id' key of a json=/data=/params= payload
        dict (resolved through one level of local variable via `assigns`), else the first positional;
      * email_send:   the recipient — a to/to_addr/recipient kwarg ONLY (a bare positional is ambiguous:
        send_email(to, ...) is to-first but sendmail(from, to, ...) is from-first, so a positional is left
        as 'unknown' rather than risk mis-reading the FROM address as the destination and under-reporting).
    `assigns` (optional {name: value_node}) lets the telegram payload-dict be resolved through a local
    variable (`payload = {...}; requests.post(url, json=payload)`)."""
    assigns = assigns or {}
    if cap == "external_write":
        dest = node.args[0] if node.args else None
        for kw in node.keywords:
            if kw.arg in ("url", "endpoint", "uri"):
                dest = kw.value
        return dest
    if cap == "telegram_send":
        for kw in node.keywords:
            if kw.arg == "chat_id":
                return _unwrap_dest(kw.value)
        for kw in node.keywords:
            if kw.arg in ("json", "data", "params"):
                d = kw.value
                if isinstance(d, ast.Name) and isinstance(assigns.get(d.id), ast.Dict):
                    d = assigns[d.id]
                if isinstance(d, ast.Dict):
                    for k, v in zip(d.keys, d.values):
                        if isinstance(k, ast.Constant) and k.value == "chat_id":
                            return _unwrap_dest(v)
        return _unwrap_dest(node.args[0]) if node.args else None
    if cap == "email_send":
        for kw in node.keywords:
            if kw.arg in ("to", "to_addr", "to_addrs", "to_email", "recipient", "recipients"):
                return _unwrap_dest(kw.value)
        return None
    return None


def _classify_dest(node, assigns=None) -> str:
    """Provenance of a destination node: 'constant' | 'config' (operator/env/settings) | 'unknown'.
    Follows one level of a simple local assignment (`chat = os.getenv(...)`) via `assigns`. A tainted
    destination is never demoted by provenance — that is the separate tainted_destination bit."""
    assigns = assigns or {}
    seen = 0
    while isinstance(node, ast.Name) and node.id in assigns and seen < 3:
        node = _unwrap_dest(assigns[node.id])
        seen += 1
    if node is None:
        return "unknown"
    if isinstance(node, ast.Constant):
        return "constant"
    if isinstance(node, ast.Call):                         # os.getenv('X') / config.get('X') -> operator config
        d = _dotted(node.func) if isinstance(node.func, ast.Attribute) else ""
        if d in ("os.getenv", "os.environ.get"):
            return "config"
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getenv") \
                and _chain_root(node) in _CONFIG_ROOTS:
            return "config"
    root = node                                            # os.environ['X'] / self.cfg.url / settings[...]
    while isinstance(root, (ast.Attribute, ast.Subscript)):
        root = root.value
    if isinstance(root, ast.Name) and root.id in _CONFIG_ROOTS:
        return "config"
    if isinstance(node, ast.Attribute) and (node.attr.endswith("_url") or node.attr.endswith("_URL")
                                            or node.attr in ("endpoint", "webhook_url")):
        return "config"
    return "unknown"                                       # bare unknown variable stays HIGH


def _dest_provenance(node, cap: str = "external_write") -> str:
    """Inline (no dataflow) destination provenance for a sink Call, used to seed the sink dict. The
    richer, dataflow-aware refinement (variable-resolved destination + taint) is analyse_destinations."""
    return _classify_dest(_dest_node(node, cap))


def _local_assigns(fnode) -> dict:
    """{name: value_node} for simple/tuple local assignments in a function — one shallow level used to
    resolve a destination bound through a variable (payload dict, chat = cfg.get(...))."""
    out = {}
    for n in ast.walk(fnode):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = n.value
                elif isinstance(t, (ast.Tuple, ast.List)) and isinstance(n.value, (ast.Tuple, ast.List)) \
                        and len(t.elts) == len(n.value.elts):
                    for te, ve in zip(t.elts, n.value.elts):
                        if isinstance(te, ast.Name):
                            out[te.id] = ve
    return out


def analyse_destinations(tree, dest_caps: dict, cli_main: bool = False) -> dict:
    """For each Call at a line in `dest_caps` ({line: capability}) resolve its DESTINATION argument
    (through one shallow level of local variable / payload-dict indirection) and return
    {line: (provenance, tainted_destination)}. provenance in {'constant','config','unknown'};
    tainted_destination True iff untrusted taint reaches the DESTINATION arg specifically (not merely
    the content). Sound-leaning: an unresolved destination -> ('unknown', False)."""
    from . import taint as _T
    out = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assigns = _local_assigns(fn)
        ft = None
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and n.lineno in dest_caps:
                cap = dest_caps[n.lineno]
                dnode = _dest_node(n, cap, assigns)
                if dnode is None:
                    continue          # this Call has no destination arg; a sibling Call on the same line
                    # (e.g. the receiver constructor in `M().send_email(...)`) may — do not clobber it.
                if ft is None:
                    ft = _T._FnTaint(fn, cli_main=cli_main)
                prov = _classify_dest(dnode, assigns)
                tainted, _ = ft.arg_taint(dnode)
                prev = out.get(n.lineno)
                if prev is None:
                    out[n.lineno] = (prov, tainted)
                else:                 # >1 real destination on one line: prefer a known provenance and, for
                    pprov, ptaint = prev   # safety, OR the taint bits (any tainted destination -> tainted).
                    out[n.lineno] = (prov if prov != "unknown" else pprov, ptaint or tainted)
    return out


class _Visitor(ast.NodeVisitor):
    def __init__(self, sym_alias=None, mod_alias=None, inst_map=None):
        self.stack: List[str] = []       # enclosing symbols
        self.auth_stack: List[bool] = []  # FP4: enclosing auth-gated routes
        self.sinks: List[dict] = []
        self.sym_alias = sym_alias or {}
        self.mod_alias = mod_alias or {}
        self.inst_map = inst_map or {}

    def _visit_scope(self, node, name):
        self.stack.append(name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node):
        # dashboard route handlers are STRUCTURAL sinks (a POST handler / @app.post decorator), not calls
        is_route = node.name in ("do_POST",) or any(
            (isinstance(d, ast.Attribute) and d.attr in ("post", "put", "delete"))
            or (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ("post", "put", "delete"))
            for d in node.decorator_list)
        if is_route:
            self.sinks.append({
                "line": node.lineno, "capability": "dashboard_mutation", "mutating": "yes",
                "sink_kind": "ast_route", "enclosing_symbol": node.name,
                # S8.94: qualify by full scope (stack does not yet include this def) so same-named route
                # handlers in different classes are distinct groups.
                "scope_path": ".".join(self.stack + [node.name]),
                "module_scope": not self.stack, "call_expr": f"route:{node.name}"})
        self.auth_stack.append(_is_auth_gated_route(node))
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()
        self.auth_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._visit_scope(node, node.name)

    def visit_Call(self, node):
        res = _classify_call(node, self.sym_alias, self.mod_alias, self.inst_map)
        if res:
            cap, mut, kind, artifact = res
            self.sinks.append({
                "line": node.lineno, "capability": cap, "mutating": "yes" if mut else "no",
                "sink_kind": kind, "enclosing_symbol": self.stack[-1] if self.stack else "",
                # S8.94 recall fix: full dotted scope path (e.g. ClassA.handle vs ClassB.handle). The GROUPING
                # key uses this so two DISTINCT methods that share a bare name are no longer collapsed into one
                # surface. `enclosing_symbol` (the bare name) is kept for display. Same-scope duplicates (two
                # sinks in the SAME function) share a scope_path and stay collapsed — intentional noise control.
                "scope_path": ".".join(self.stack),
                "module_scope": not self.stack,
                "call_expr": _chain_str(node.func) or _attr_name(node.func) or "",
                "auth_gated": any(self.auth_stack),                              # FP4
                "dest_provenance": _dest_provenance(node, cap) if cap in _DEST_AWARE_CAPS else "unknown",  # FP3/Fix1
                # S8.46: a subprocess is command-injectable only when the arg is SHELL-INTERPRETED (shell=True or
                # an always-shell function). subprocess.run([list]) without shell is NOT injection via a data arg.
                "shell_form": _subprocess_shell_form(node) if cap == "subprocess_exec" else True,
            })
        self.generic_visit(node)


_ALWAYS_SHELL = {"system", "popen", "getoutput", "getstatusoutput", "getstatus", "create_subprocess_shell"}


def _subprocess_shell_form(node):
    """S8.46: is this subprocess call SHELL-interpreted (so a tainted arg = command injection)? True iff
    shell=True, or it's an always-shell function (os.system/os.popen/getoutput/create_subprocess_shell).
    subprocess.run([list])/Popen without shell=True passes args literally -> a tainted DATA arg is NOT
    injection (the CEO's repo pattern). Sound-leaning: unsure -> False (downgrade), tainted-executable
    (cmd[0]) is a rarer case left to a future refinement."""
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    tail = ((_dotted(node.func) or _attr_name(node.func) or "").split(".")[-1])
    return tail in _ALWAYS_SHELL


def _dead_line_ranges(tree):
    """FP1: line spans of statements that follow an UNCONDITIONAL raise/return that is a DIRECT sibling in a
    suite -> dead code, cannot execute, not a sink. Only direct-sibling Return/Raise (conditional/nested exits
    and break/continue/exit-calls never qualify), same suite only (except/finally/else are separate suites)."""
    dead = []
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            suite = getattr(node, field, None)
            if not isinstance(suite, list):
                continue
            for i, stmt in enumerate(suite):
                if isinstance(stmt, (ast.Return, ast.Raise)):
                    for ds in suite[i + 1:]:
                        dead.append((ds.lineno, getattr(ds, "end_lineno", ds.lineno)))
                    break
    return dead


def detect(text: str):
    """Return (ok, sinks). ok=False -> AST parse failed (caller uses regex fallback)."""
    try:
        tree = ast.parse(text)
    except Exception:
        return False, []
    sym_alias, mod_alias = _collect_aliases(tree)
    inst_map = _collect_instances(tree, sym_alias, mod_alias)
    v = _Visitor(sym_alias, mod_alias, inst_map)
    v.visit(tree)
    dead = _dead_line_ranges(tree)
    if dead:
        return True, [s for s in v.sinks
                      if not any(lo <= s.get("line", -1) <= hi for lo, hi in dead)]
    return True, v.sinks
