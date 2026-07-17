"""Hermes Shield MVP-1A — detection patterns (read-only knowledge base). No secrets."""
from __future__ import annotations
import re

# (capability, risk, compiled regex). Ordered: first match wins per line for the primary label.
_RAW_ACTION = [
    # outbound / social
    ("post", "critical", r"\bcreate_tweet\b|\bpost_tweet\b|x_api_publish|publish_thread\b"),
    ("reply", "critical", r"\bpost_reply\b|create_tweet\([^)]*in_reply_to|reply_to_tweet"),
    ("retweet", "high", r"\bretweet\b|\bquote_tweet\b"),
    ("like", "high", r"\bcreate_favorite\b|\blike_tweet\b|\.like\("),
    ("comment", "high", r"linkedin_.*comment|post_comment\b"),
    ("post", "critical", r"linkedin_live_bridge|linkedin_.*post\b|_post_linkedin"),
    ("telegram_send", "high", r"send_message\([^)]*chat_id|bot\.send_message|tg_send\(|telegram.*\.send\("),
    # email
    ("email_send", "critical", r"messages\(\)\.send|\.sendmail\(|smtplib|send_email\b|send_draft\b"),
    # browser / cdp / computer-use
    ("browser_click", "high", r"page\.click\(|element\.click\(|locator\([^)]*\)\.click|\.click\(\)\s*#.*cdp"),
    ("browser_type", "high", r"page\.type\(|\.fill\(|send_keys\("),
    ("browser_submit", "high", r"\.submit\(\)|press\(['\"]Enter"),
    ("computer_use", "high", r"xdotool|computer_use|pyautogui|\.keyDown\("),
    ("browser_click", "medium", r"playwright|selenium|ChromiumPage|CDP\b"),
    # state mutation
    ("queue_mutation", "high", r"UPDATE\s+x_post_queue|INSERT\s+INTO\s+x_post_queue|DELETE\s+FROM\s+x_post_queue"),
    ("approval_mutation", "high", r"set\s+.*review_status|mark.*approved|record_approved|status\s*=\s*['\"]approved"),
    ("cron_mutation", "high", r"crontab\s+-|write.*crontab|CronCreate"),
    ("env_mutation", "high", r"\.env['\"]?\s*,\s*['\"]a|write.*\.env|os\.environ\[[^]]+\]\s*="),
    # P2.9B — outbound / exec / publish sinks (false-negative closure)
    ("external_write", "high", r"\b(requests|httpx)\.(post|put|patch|delete)\("),
    ("external_read", "low", r"\b(requests|httpx)\.get\("),
    ("subprocess_exec", "high", r"\bsubprocess\.(run|Popen|call|check_call|check_output)\(|\bos\.system\("),
    ("post", "high", r"api\.update_status\(|api\.create_tweet\(|\.send_direct_message\(|\.media_upload\("),
    ("publish_write", "high", r"open\([^)]*(ready|approved|publish|postable|outbound)[^)]*['\"][wa]"),
    # model / vision / ingest
    ("vision_model_call", "medium", r"input_image|image_url.*data:image|vision"),
    ("model_call", "low", r"client\.responses\.create|chat\.completions\.create|messages\.create\(|OpenAI\(|Anthropic\("),
    ("pdf_ocr_ingest", "medium", r"pytesseract|ocr_text|extract_text|PdfReader|pdfplumber"),
    # dashboard / web routes
    ("dashboard_mutation", "high", r"def\s+do_POST|@app\.post|@router\.post|methods=\[['\"]POST"),
]
# capabilities that mutate/act (vs read-only). external_read is deliberately NOT here.
MUTATING_CAPS = {"deserialize", "code_exec", "ssti", "secret_exfil", "cloud_write", "blockchain_tx", "payment", "file_perms", "tool_invoke", "file_delete", "post", "reply", "comment", "like", "dm", "email_send", "telegram_send",
                 "browser_click", "browser_type", "browser_submit", "computer_use",
                 "queue_mutation", "external_write", "subprocess_exec", "publish_write",
                 "dashboard_mutation", "approval_mutation", "cron_mutation", "env_mutation"}
READONLY_CAPS = {"external_read", "model_call", "pdf_ocr_ingest", "vision_model_call"}
ACTION_PATTERNS = [(cap, risk, re.compile(rx, re.I)) for cap, risk, rx in _RAW_ACTION]

# untrusted ingress sources
_RAW_INGRESS = [
    ("x_post", r"tweet.*text|post.*text|third_party.*tweet|reply.*text|feed.*text"),
    ("linkedin", r"linkedin.*(post|comment|profile).*text|li_.*text"),
    ("email", r"email.*body|message.*body|gmail.*body|reply.*body"),
    ("web", r"article.*text|news.*text|scrape|requests\.get|urllib.*urlopen|fetch.*html"),
    ("github", r"readme|repo.*description|github.*(description|content)"),
    ("pdf", r"pdf.*text|extract_text|PdfReader"),
    ("ocr", r"ocr_text|pytesseract|image.*text"),
    ("telegram", r"telegram.*(message|callback|update)|getUpdates|callback_data"),
    ("dashboard", r"parse_qs|request\.form|self\.rfile\.read|input.*value"),
    ("api", r"response\.json\(\)|payload\[|external.*api"),
]
INGRESS_PATTERNS = [(src, re.compile(rx, re.I)) for src, rx in _RAW_INGRESS]

# guard markers
GUARD_MARKERS = {
    "kill_switch": re.compile(r"assert_live_action_allowed|hermes_global_kill_switch|shield_kill_switch|GLOBAL KILL SWITCH", re.I),
    "final_action_gate": re.compile(r"final_action_gate|allow_action\(|FinalActionDecision", re.I),
    "strict_hash": re.compile(r"content_hash|hash_ledger|approved_hash|get_approved\(", re.I),
    "dry_run": re.compile(r"dry_run|--dry-run|DRY_RUN|live\s*=\s*False|allow_model=False", re.I),
    "human_approval": re.compile(r"human_approved|requires_human|approval.*callback|--approve\b|await_approval", re.I),
    "csrf_token": re.compile(r"is_dashboard_post_allowed|dashboard_auth|X-Hermes-Token|csrf", re.I),
    "untrusted_fence": re.compile(r"hermes_untrusted|make_untrusted_content|wrap_for_prompt|wrap_for_action_prompt|classify\(|quarantin|screen_source|_fence_untrusted", re.I),
}
FENCE_MARKERS = re.compile(
    r"hermes_untrusted|make_untrusted_content|wrap_for_prompt|wrap_for_action_prompt|"
    r"classify\(|quarantin|screen_source|_fence_untrusted|_their_fenced|drop_hostile", re.I)

# directory / file context heuristics
DEAD_FILE = re.compile(r"backup|_202[0-9]{5}|\.bak|\.old|\.orig|\bcopy\b|_deprecated", re.I)
TEST_HINT = re.compile(r"(^|/)(tests?|_test|test_)|conftest", re.I)
REPORT_HINT = re.compile(r"(^|/)(reports?|docs|programme_memory)/|\.md$", re.I)
DEV_HINT = re.compile(r"(^|/)(scratch|examples?|samples?|demos?|cookbook|recipes?|tutorials?|notebooks?|sandbox|benchmarks?|mock_lanes|corpus)/|_test_send|_demo|mock_lane|corpus_fixture", re.I)
# P2.9B FP-reduction context: debug/probe files, read-only collectors/scanners, generator functions
DEBUG_HINT = re.compile(r"_debug|debug_|_probe|probe_|_inspect|inspect_|_diag|diag_|scratch", re.I)
COLLECTOR_HINT = re.compile(r"collect_|_collector|_scraper|scrape_|_reader|read_only|_scan\b|scanner", re.I)
GENERATOR_SYMBOL = re.compile(r"^(generate_|build_|make_|render_|compose_|draft_|format_)", re.I)

# dirs to skip entirely (perf + not the target's own code — incl. vendored third-party trees, S8.85)
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "worktrees",
             "local_only_extraction", "local_only_backups", "shield_visual_reference",
             ".pytest_cache", "site-packages",
             "vendor", "third_party", "contrib"}

CRITICAL_CAPS = {"deserialize", "code_exec", "ssti", "secret_exfil", "cloud_write", "blockchain_tx", "payment", "file_perms", "tool_invoke", "file_delete", "post", "reply", "comment", "like", "dm", "email_send", "telegram_send",
                 "browser_click", "browser_type", "browser_submit", "computer_use", "queue_mutation",
                 "external_write", "subprocess_exec", "publish_write"}
