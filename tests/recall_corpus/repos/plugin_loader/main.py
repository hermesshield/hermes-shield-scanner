"""Plugin host. UNTRUSTED INGRESS: the plugin name, hook name and payload are
read from a job description (queue/config) that an operator or upstream job
controls. Two dispatch styles exercise both loader paths.
"""
import importlib
import json
import sys

from loader import load_and_run, run_hook


def handle_job(job):
    # job is untrusted JSON: {"module", "func", "hook", "payload"}
    if job.get("func"):
        return load_and_run(job["module"], job["func"], job["payload"])
    mod = importlib.import_module(job["module"])
    return run_hook(mod, job["hook"], job["payload"])


if __name__ == "__main__":
    job = json.loads(sys.argv[1])
    print(handle_job(job))
