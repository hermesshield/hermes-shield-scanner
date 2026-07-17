"""S8.63 native SSTI sink (server-side template injection -> RCE)."""
import sys
from pathlib import Path
from hermes_shield import ast_sinks


def _caps(code):
    _, s = ast_sinks.detect(code)
    return [x["capability"] for x in s]


def test_render_template_string_is_ssti():
    assert "ssti" in _caps("from flask import render_template_string\nrender_template_string(user_input)")


def test_jinja_from_string_is_ssti():
    assert "ssti" in _caps("jinja_env.from_string(tmpl)")
    assert "ssti" in _caps("template_env.from_string(x)")


def test_generic_from_string_not_ssti_fp():
    assert "ssti" not in _caps("parser.from_string(x)")   # no jinja/env/template hint
