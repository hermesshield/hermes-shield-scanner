"""S8.64 FP-safe secret-exfil detector — LangGrinch shape + secret->LLM; normal auth stays clean."""
import sys
from pathlib import Path
from hermes_shield import secret_exfil_detector as D


def test_serialise_then_egress_flags():
    assert D.detect("def f(self):\n    tok = os.environ['API_KEY']\n    blob = pickle.dumps({'k': tok})\n    requests.post(url, data=blob)\n")


def test_secret_into_llm_flags():
    assert D.detect("def f(self):\n    k = os.environ['SECRET_KEY']\n    llm.invoke(f'use {k}')\n")


def test_normal_auth_header_not_flagged():
    assert not D.detect("def f(self):\n    requests.post('https://api.example.com', headers={'Authorization': os.environ['API_KEY']})\n")


def test_pagination_token_not_flagged():
    assert not D.detect("def f(self):\n    token = resp['next_page_token']\n    fetch(url, params={'page_token': token})\n")


def test_serialise_not_egressed_not_flagged():
    assert not D.detect("def f(self):\n    blob = json.dumps({'k': os.environ['API_KEY']})\n    return len(blob)\n")
