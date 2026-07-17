"""Make `pytest` work from a bare checkout (before `pip install -e .`): expose the src/ layout on sys.path.
Test-time only — no runtime behaviour changes. A normal editable install makes this a no-op."""
import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
