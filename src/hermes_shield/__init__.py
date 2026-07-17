"""Hermes Shield — read-only static scanner for AI-agent codebases.
CLI entry point: shield_cli.main() (installed as `hermes-shield`). Never writes to the target repo, never reads secrets."""
from .models import SCANNER_VERSION  # noqa: F401
