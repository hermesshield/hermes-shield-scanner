"""A benign reporting plugin — DECOY. Pure in-memory computation, no capability
of any kind.
"""


def execute(rows):
    # DECOY D06 — benign: summarises rows and returns a dict. No sink.
    total = sum(int(r.get("value", 0)) for r in rows)
    return {"count": len(rows), "total": total}
