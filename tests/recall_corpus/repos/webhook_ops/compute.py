"""A 'formula' evaluator for webhook rules. The eval builtin is aliased to
`_calc` at module load, so no literal eval( call is ever written.
"""

# aliasing: the code-execution primitive hidden behind an innocuous name
_calc = eval


def run_formula(expr, context):
    # PLANTED S06 — arbitrary code execution: `expr` is a webhook-supplied
    # rule string, evaluated through the `_calc` alias of eval.
    return _calc(expr, {}, dict(context))
