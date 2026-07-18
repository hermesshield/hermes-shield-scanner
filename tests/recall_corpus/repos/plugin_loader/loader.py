"""Config-driven plugin loader. The module name and hook name both come from
user/config input, so the import target and the invoked attribute are dynamic.
"""
import importlib


def load_and_run(module_name, func_name, payload):
    # PLANTED S12 — importlib import of a config-named module followed by an
    # immediate getattr(...)-call of a config-named function. Static catches the
    # dynamic dispatch (capability-generic) at this site.
    mod = importlib.import_module(module_name)
    return getattr(mod, func_name)(payload)


def run_hook(mod, hook_name, data):
    # PLANTED S13 — the hook attribute is bound to a local via getattr then
    # invoked. Assigned-form dispatch — static tends to miss it.
    handler = getattr(mod, hook_name)
    return handler(data)
