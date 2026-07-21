#!/usr/bin/env python3
"""
Hermes Shield — command-line interface. Read-only static scanner for AI-agent codebases.

It never mutates the target repo and never takes a live action. Outputs are written to
./shield-report/ in the current directory (override with --out or HERMES_SHIELD_OUT).

Usage:
  hermes-shield scan <repo>                  # deterministic core scan (default)
  hermes-shield scan <repo> --ai             # + per-file AI-assist recall (fast; needs `claude` CLI)
  hermes-shield scan <repo> --ai-deep        # + whole-repo agentic AI finder (slower+deeper; needs `claude` CLI)
  hermes-shield scan <repo> --semgrep        # + semgrep comparator (multi-language breadth)
  hermes-shield scan                         # no target: enclosing git repo, or an interactive picker
  hermes-shield demo                         # scan a bundled deliberately-vulnerable toy agent (~10s)
  hermes-shield diff <repo>                  # scan + compare against the saved baseline
  hermes-shield export-dashboard <repo>      # scan + dashboard export JSON
  hermes-shield patch-plan <repo>            # scan + patch-plan JSON
  hermes-shield version                      # (also: hermes-shield --version)

Detection modes:
  core       deterministic static analysis (Python: sinks + taint + guard proof; TS/JS + C#: sinks only).
             Reproducible: same input -> same output.
  --semgrep  runs semgrep as an ISOLATED comparator tier (never merged into the core headline).
             Deterministic; needs `semgrep` installed. Env equivalent: HERMES_SHIELD_SEMGREP=1.
  --ai       AI-assist tier: fast, per-FILE recall of NOVEL sinks the static rules missed; every
             proposal is AST-verified and kept in a separate AI_SUSPECTED tier. NON-deterministic
             (uses your own local `claude` CLI auth — sends code to Anthropic under YOUR account;
             no key is stored in this package). OFF by default. Env equivalent: HERMES_SHIELD_AI_TIER=1.
  --ai-deep  whole-REPO agentic AI finder — slower + deeper than --ai (reads across the repo); the
             same pass offered by the interactive post-scan prompt. Advisory; OFF by default.

For reproducible / audit runs use core (optionally + --semgrep). --ai improves hit-rate but is
non-deterministic; its findings are advisory and never counted in the deterministic headline.
"""
from __future__ import annotations
import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from .models import SCANNER_VERSION
from . import scan_hermes


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# WORKSTREAM C — offer the deeper AI pass after a STATIC-only scan. HUMAN-on-a-terminal ONLY: the prompt is
# read from stdin, so it must NEVER fire in a non-TTY / piped / CI run (it would hang a script). Gated on
# stdin.isatty() + the `claude` CLI present + not --quiet + the deep pass not already requested. The prompt
# goes to STDERR so stdout stays script-clean.
# ---------------------------------------------------------------------------

def _should_offer_ai_pass(args, ai_deep_effective: bool) -> bool:
    """True only when it is safe + sensible to OFFER the deeper AI pass interactively: a `scan` command that
    ran STATIC-only (no --ai / --ai-deep), a human at the keyboard (stdin isatty), the `claude` CLI on PATH,
    colourful output allowed (not --quiet), and no opt-out (HERMES_SHIELD_NO_PROMPT)."""
    return (getattr(args, "command", None) == "scan"
            and not ai_deep_effective
            and not getattr(args, "ai", False)
            and not getattr(args, "quiet", False)
            and sys.stdin.isatty()
            and _tool_available("claude")
            and not os.getenv("HERMES_SHIELD_NO_PROMPT"))


def _prompt_yes_no(question: str, stdin=None, stderr=None) -> bool:
    """Write `question` to STDERR and read ONE line from stdin. Returns True only for y/yes (case-insensitive).
    Empty line / N / EOF / any read error -> False. Only ever called on an interactive TTY."""
    stdin = stdin if stdin is not None else sys.stdin
    stderr = stderr if stderr is not None else sys.stderr
    try:
        stderr.write(question)
        stderr.flush()
        line = stdin.readline()
    except (KeyboardInterrupt, OSError, EOFError):
        return False
    return (line or "").strip().lower() in ("y", "yes")


# ---------------------------------------------------------------------------
# No-arg target resolution ("detect & pick") — CLI-layer only. scan_hermes's own
# current_repo_root() fallback is unchanged; the CLI resolves a target explicitly
# so it can EXPLAIN the choice (and, on a TTY, offer a picker). All guidance goes
# to STDERR so stdout stays script-clean. Never blocks on stdin in a pipe.
# ---------------------------------------------------------------------------

_PICKER_SKIP_DIRS = {"node_modules", ".venv", "venv"}
_PICKER_MAX_CANDIDATES = 20
_PICKER_MAX_DEPTH = 2


def _enclosing_git_repo(start: Path | None = None) -> Path | None:
    """Nearest enclosing git repo of `start` (default: the CWD), else None.
    Mirrors scan_hermes.current_repo_root() but distinguishes 'no repo' from 'CWD'."""
    p = (start or Path.cwd()).resolve()
    for a in (p, *p.parents):
        if (a / ".git").exists():
            return a
    return None


def _interactive() -> bool:
    """True only when a human is plausibly at the keyboard: both stdin and stderr are
    TTYs, we're not in CI, and the operator hasn't opted out via HERMES_SHIELD_NO_PROMPT."""
    return (sys.stdin.isatty() and sys.stderr.isatty()
            and not os.getenv("CI") and not os.getenv("HERMES_SHIELD_NO_PROMPT"))


def _candidate_git_dirs(root: Path, max_depth: int = _PICKER_MAX_DEPTH,
                        cap: int = _PICKER_MAX_CANDIDATES) -> list[Path]:
    """Bounded scan for child dirs that look like git repos: depth <= max_depth, at most
    `cap` results, skipping hidden dirs and node_modules/.venv/venv. Deterministic order."""
    found: list[Path] = []

    def walk(d: Path, depth: int) -> None:
        if len(found) >= cap:
            return
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            if len(found) >= cap:
                return
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if e.name.startswith(".") or e.name in _PICKER_SKIP_DIRS:
                continue
            p = Path(e.path)
            if (p / ".git").exists():
                found.append(p)          # a repo — don't descend into it
            elif depth < max_depth:
                walk(p, depth + 1)

    walk(root, 1)
    return found


def _prompt_pick(cwd: Path, candidates: list[Path], stdin=None, stderr=None) -> Path:
    """Numbered picker on STDERR; reads ONE line. Empty/invalid/EOF -> the CWD default.
    Only ever called on an interactive TTY (see _interactive)."""
    stdin = stdin if stdin is not None else sys.stdin
    stderr = stderr if stderr is not None else sys.stderr
    print("hermes-shield: the current directory is not inside a git repo. "
          "Pick a scan target:", file=stderr)
    print("  0) scan this directory (default)", file=stderr)
    for i, c in enumerate(candidates, 1):
        try:
            shown = c.relative_to(cwd)
        except ValueError:
            shown = c
        print(f"  {i}) {shown}", file=stderr)
    stderr.write("> ")
    stderr.flush()
    try:
        line = stdin.readline()
    except (KeyboardInterrupt, OSError):
        return cwd
    choice = (line or "").strip()
    if choice.isdigit() and 0 <= int(choice) <= len(candidates):
        n = int(choice)
        return cwd if n == 0 else candidates[n - 1]
    return cwd


def _resolve_scan_target() -> Path:
    """Resolve the target for `hermes-shield scan` with no path argument.
    (a) enclosing git repo -> use it, say so on stderr.
    (b) no repo + interactive TTY -> bounded picker over child git repos.
    (c) no repo + non-TTY/piped/CI -> today's behaviour (scan the CWD) + a clear stderr note."""
    repo = _enclosing_git_repo()
    if repo is not None:
        print(f"hermes-shield: scanning {repo} (enclosing git repo of the current directory) "
              "— pass a path to choose another", file=sys.stderr)
        return repo
    cwd = Path.cwd().resolve()
    if _interactive():
        candidates = _candidate_git_dirs(cwd)
        if candidates:
            return _prompt_pick(cwd, candidates)
        print(f"hermes-shield: no git repo found — scanning the current directory {cwd} "
              "(pass a path to choose another)", file=sys.stderr)
        return cwd
    print(f"hermes-shield: no target given and no enclosing git repo — scanning the current "
          f"directory {cwd} (pass a path to choose another)", file=sys.stderr)
    return cwd


# ---------------------------------------------------------------------------
# `hermes-shield demo` — a real red report in ~10 seconds. The fixtures ship inside
# the wheel as INERT package data (_demo/*.py.txt — not importable, clearly labelled);
# demo copies them into a throwaway temp dir under real .py names and runs the normal
# scan path against that copy. Nothing is ever executed from the fixtures.
# ---------------------------------------------------------------------------

_DEMO_FILES = ("app.py", "tools.py")


def _materialise_demo_target() -> Path:
    from importlib import resources
    tmp = Path(tempfile.mkdtemp(prefix="hermes-shield-toy-agent-"))
    pkg = resources.files("hermes_shield") / "_demo"
    for name in _DEMO_FILES:
        (tmp / name).write_text((pkg / f"{name}.txt").read_text(encoding="utf-8"),
                                encoding="utf-8")
    return tmp


def _run_demo(args) -> int:
    target = _materialise_demo_target()
    live = getattr(args, "live", False)
    print("demo target — a deliberately vulnerable toy agent")
    print(f"  a Flask route that eval()s attacker JSON (reachable-live) + an inert shell "
          f"capability (install-liability), copied to {target}")
    passthrough = (["--scan", "--root", str(target)]
                   + (["--out", args.out] if args.out else [])
                   + (["--live"] if live else [])
                   + (["--quiet"] if args.quiet else []))
    rc = scan_hermes.main(passthrough)
    out_dir, _ = scan_hermes.resolve_out_paths(target, args.out)
    # --live on a TTY already closes on the report path (the finale prints it), so skip the redundant line
    # there. Off a TTY the finale never runs, so keep the pointer — piped `demo --live` still shows it.
    live_tty = live and sys.stdout.isatty()
    if not args.quiet and not live_tty:
        print(f"  full report: {out_dir / 'shield_customer_report.html'}")
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="hermes-shield",
        description="Hermes Shield scanner (local, read-only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit code: hermes-shield returns 0 regardless of findings (a RED report does NOT fail the\n"
               "process). For CI gating, parse the verdict from the report JSON\n"
               "(shield-report/outputs/hermes_shield_report.json). A --fail-on flag is a future enhancement.")
    ap.add_argument("--version", action="version",
                    version=f"hermes-shield scanner {SCANNER_VERSION}")
    sub = ap.add_subparsers(dest="command")
    for name in ("scan", "diff", "export-dashboard", "patch-plan"):
        sp = sub.add_parser(name)
        sp.add_argument("target", nargs="?", default=None,
                        help="target repo path (default: enclosing git repo of the CWD)")
        sp.add_argument("--target", dest="target_opt", default=None, help=argparse.SUPPRESS)
        sp.add_argument("--out", default=None,
                        help="output dir for scan artefacts (default: ./shield-report/ in the CWD)")
        sp.add_argument("--ai", action="store_true",
                        help="AI-assist: fast, per-FILE novel-sink recall (uses your local `claude`, sends "
                             "code to Anthropic under YOUR account). Advisory, non-deterministic; OFF by "
                             "default. For the whole-repo, slower + deeper pass see --ai-deep.")
        sp.add_argument("--ai-backend", dest="ai_backend", choices=("claude", "ollama"), default=None,
                        help="AI-assist backend transport (default: claude, the historical path). "
                             "'ollama' runs a LOCAL, zero-egress model via localhost Ollama "
                             "(HERMES_SHIELD_OLLAMA_HOST / HERMES_SHIELD_OLLAMA_MODEL). Only meaningful "
                             "with --ai; absent => claude (byte-identical to today).")
        sp.add_argument("--semgrep", action="store_true",
                        help="enable the semgrep comparator tier (multi-language breadth; "
                             "deterministic; needs `semgrep` installed)")
        sp.add_argument("--all", dest="all_modes", action="store_true",
                        help="full coverage: run the core + --semgrep + --ai in one command")
        sp.add_argument("--deps", action="store_true",
                        help="dependency-aware scan: also fetch + scan the repo's OWN pinned first-party "
                             "packages (catches a capability relocated into a dep not in the tree; needs "
                             "network + pip; static only, never installs/executes; OFF by default). Not "
                             "included in --all because it reaches the network.")
        if name == "scan":
            # Phase-1 PROVEN-LIVE self-attack lane — ONLY on `scan`. Consent-gated, OFF by default, and
            # deliberately NOT part of --all (it EXECUTES target code in a sandbox). Same loud warning +
            # consent as `demo --prove`.
            sp.add_argument("--prove", action="store_true",
                            help="PROVEN-LIVE self-attack lane (Phase 1): after the read-only scan, EXECUTE "
                                 "the drivable candidate RCE sinks of the REAL target inside a sandbox to "
                                 "prove they are live (benign canary, no network). Consent-gated; OFF by "
                                 "default; NOT part of --all. Only run this on a repo you trust.")
            sp.add_argument("--yes-execute-my-code", dest="yes_execute", action="store_true",
                            help="non-interactive consent for --prove (also: HERMES_SHIELD_PROVE_CONSENT=1)")
            # Whole-repo AGENTIC AI finder (SEPARATE from --ai's per-file tier). Reads ACROSS the repo via the
            # read-only agentic `claude` CLI to surface agent-plumbing static misses; findings are AST-verified
            # and appended as ADVISORY ai_suspected surfaces, never in the deterministic headline. OFF by
            # default => byte-identical scan. Degrades gracefully if `claude` is absent (like --ai).
            sp.add_argument("--ai-deep", dest="ai_deep", action="store_true",
                            help="whole-REPO agentic AI finder — slower + deeper than --ai; same as accepting "
                                 "the post-scan prompt. Advisory ai_suspected surfaces; reads across the repo; "
                                 "non-deterministic; Claude-only for now — needs the `claude` CLI, and "
                                 "--ai-backend does NOT apply to it; OFF by default. "
                                 "Env equivalent: HERMES_SHIELD_AI_FINDER=1.")
        sp.add_argument("--live", action="store_true",
                        help="the live HUD is now the DEFAULT on a terminal; --live is kept as a no-op alias. "
                             "Use --quiet for plain output. (The HUD stays TTY-only: a non-TTY/piped run always "
                             "gets byte-clean, JSON-safe stdout, whether or not --live is passed.)")
        sp.add_argument("--quiet", action="store_true",
                        help="plain, JSON-safe stdout with no live HUD — the CI / agent / JSON-piping mode "
                             "(a non-TTY/piped run is already byte-clean; --quiet also silences a TTY run).")
    dp = sub.add_parser("demo",
                        help="scan a bundled, deliberately vulnerable toy agent — a real red "
                             "report in ~10 seconds (fixtures ship as inert .txt package data, "
                             "copied to a temp dir; nothing is executed)")
    dp.add_argument("--out", default=None,
                    help="output dir for scan artefacts (default: ./shield-report/ in the CWD)")
    dp.add_argument("--prove", action="store_true",
                    help="PROVEN-LIVE self-attack lane (Phase 0): EXECUTES the bundled demo fixture "
                         "inside a sandbox to prove a code_exec sink is live (benign canary, no network). "
                         "Consent-gated; OFF by default; NOT part of --all. Only ever runs on a repo you "
                         "trust — in Phase 0 it is contained to the bundled fixture.")
    dp.add_argument("--yes-execute-my-code", dest="yes_execute", action="store_true",
                    help="non-interactive consent for --prove (also: HERMES_SHIELD_PROVE_CONSENT=1)")
    dp.add_argument("--live", action="store_true",
                    help="the live HUD is now the DEFAULT on a terminal; --live is kept as a no-op alias. "
                         "Use --quiet for plain output. (The HUD stays TTY-only; a non-TTY/piped run is "
                         "unchanged whether or not --live is passed.)")
    dp.add_argument("--quiet", action="store_true",
                    help="plain, JSON-safe stdout with no live HUD — the CI / agent / JSON-piping mode "
                         "(a non-TTY/piped run is already byte-clean; --quiet also silences a TTY run).")
    sub.add_parser("version")
    args = ap.parse_args(argv)

    # Bare `hermes-shield` is a first-run, not an error: print help and exit 0.
    if args.command is None:
        ap.print_help()
        return 0

    if args.command == "demo":
        # --prove is the consent-gated PROVEN-LIVE self-attack lane (Phase 0), contained to the bundled
        # fixture. It NEVER touches the default `demo` scan path below (byte-identical when --prove is off).
        if getattr(args, "prove", False):
            from . import prove
            return prove.run_prove_demo_cli(out=args.out, assume_yes=getattr(args, "yes_execute", False),
                                            quiet=args.quiet)
        return _run_demo(args)

    # --all is a convenience for full coverage: core + semgrep + ai in a single scan.
    if getattr(args, "all_modes", False):
        args.ai = True
        args.semgrep = True

    if args.command == "version":
        print(f"hermes-shield scanner {SCANNER_VERSION}")
        return 0

    target = args.target or args.target_opt
    if args.command == "scan" and target is None:
        # detect & pick (CLI layer only): enclosing git repo, else TTY picker, else CWD.
        target = str(_resolve_scan_target())

    # --ai / --semgrep are thin, documented switches over the underlying env flags.
    # Both degrade gracefully: a missing external tool never blocks the core scan.
    if args.ai:
        if _tool_available("claude"):
            os.environ["HERMES_SHIELD_AI_TIER"] = "1"
        else:
            print("hermes-shield: --ai not available — the `claude` CLI is not installed/on PATH. "
                  "Install Claude Code (https://claude.com/claude-code) and authenticate, then retry. "
                  "Continuing with the deterministic core scan.", file=sys.stderr)
    # --ai-backend is additive: it only selects the transport for the AI tier. Absent => the env stays
    # unset => the tier defaults to "claude" (byte-identical to today). Set only when explicitly chosen so
    # a plain --ai run is unchanged.
    if getattr(args, "ai_backend", None):
        os.environ["HERMES_SHIELD_AI_BACKEND"] = args.ai_backend
    # --ai-deep is the whole-repo agentic finder gate. Like --ai it degrades gracefully: a missing `claude`
    # CLI never blocks the core scan. When available it sets the env gate run_scan reads (propagated to the
    # in-process scan_hermes.main call below via the shared os.environ) so the finder actually fires.
    ai_deep = getattr(args, "ai_deep", False)
    if ai_deep:
        if _tool_available("claude"):
            os.environ["HERMES_SHIELD_AI_FINDER"] = "1"
        else:
            print("hermes-shield: --ai-deep not available — the `claude` CLI is not installed/on PATH. "
                  "Install Claude Code (https://claude.com/claude-code) and authenticate, then retry. "
                  "Continuing with the deterministic core scan.", file=sys.stderr)
            ai_deep = False
    if args.semgrep:
        if _tool_available("semgrep"):
            os.environ["HERMES_SHIELD_SEMGREP"] = "1"
            os.environ.setdefault("HERMES_SHIELD_SEMGREP_MODE", "venv")   # = the semgrep binary on PATH
        elif _tool_available("docker"):
            os.environ["HERMES_SHIELD_SEMGREP"] = "1"
            os.environ.setdefault("HERMES_SHIELD_SEMGREP_MODE", "docker")
        else:
            print("hermes-shield: --semgrep not available — `semgrep` is not installed (and no docker). "
                  "Install it in an isolated env (e.g. `pipx install semgrep`) and retry. "
                  "Continuing with the deterministic core scan.", file=sys.stderr)
    if getattr(args, "deps", False):
        if _tool_available("pip") or _tool_available("pip3"):
            os.environ["HERMES_SHIELD_DEPS"] = "1"
        else:
            print("hermes-shield: --deps not available — `pip` is not on PATH. "
                  "Continuing with the tree scan only.", file=sys.stderr)

    flags = {"scan": ["--scan"], "diff": ["--diff"],
             "export-dashboard": ["--scan"], "patch-plan": ["--scan"]}[args.command]
    passthrough = (flags + (["--root", target] if target else [])
                   + (["--out", args.out] if args.out else [])
                   + (["--live"] if getattr(args, "live", False) else [])
                   + (["--quiet"] if args.quiet else []))
    # --prove is a `scan`-only, consent-gated add-on. Pass it (and its consent flag) straight through to the
    # scan engine, which prints the loud warning + gates before anything executes. NOT part of --all.
    if getattr(args, "prove", False):
        passthrough += ["--prove"]
        if getattr(args, "yes_execute", False):
            passthrough += ["--yes-execute-my-code"]
    # Pass --ai-deep through too (only when `claude` is present — see the graceful-degrade gate above) so the
    # finder fires whether shield_cli reaches the engine in-process (shared env) or, in future, via subprocess.
    if ai_deep:
        passthrough += ["--ai-deep"]

    # WORKSTREAM C: when the scan will run STATIC-only but the deeper AI pass is available + we're interactive,
    # we OFFER it after the scan. To keep exactly ONE auto-open across the (possible) two passes, DEFER the
    # scan-engine's auto-open for the first (static) pass via HERMES_SHIELD_NO_AUTO_OPEN, then re-open once the
    # offer resolves. (If the operator set that env themselves, we honour it end-to-end and never auto-open.)
    will_offer = _should_offer_ai_pass(args, ai_deep)
    user_opted_out_open = bool(os.getenv("HERMES_SHIELD_NO_AUTO_OPEN"))
    if will_offer and not user_opted_out_open:
        os.environ["HERMES_SHIELD_NO_AUTO_OPEN"] = "1"

    rc = scan_hermes.main(passthrough)

    if will_offer:
        say_yes = _prompt_yes_no("Run the deeper AI pass (--ai-deep) now? (uses your Claude) [y/N] ")
        if not user_opted_out_open:
            os.environ.pop("HERMES_SHIELD_NO_AUTO_OPEN", None)   # restore for the branch below / re-run
        if say_yes:
            # Run the whole-repo agentic AI finder (its live feed shows) and REGENERATE the report. The re-run
            # auto-opens the freshly regenerated report (one open total).
            os.environ["HERMES_SHIELD_AI_FINDER"] = "1"
            rc = scan_hermes.main(passthrough + ["--ai-deep"])
        elif not user_opted_out_open:
            # Declined: open the static report we already generated (the single deferred auto-open), fire-and-
            # forget, TTY-only, never in CI. Errors swallowed inside open_report.auto_open.
            if sys.stdout.isatty() and not os.getenv("CI"):
                from . import open_report as _OR
                _out_dir, _ = scan_hermes.resolve_out_paths(Path(target).resolve() if target else None, args.out)
                _OR.auto_open(_OR.report_abspath(_out_dir))

    if args.command in ("export-dashboard", "patch-plan") and not args.quiet:
        print("artefacts written under the scan output dir (default ./shield-report/outputs)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
