"""Refund path — DECOY. The Stripe refund only fires behind a dry-run switch
and an explicit human-approval gate, so a precision-correct scanner attributes
the guards rather than reporting an unguarded live payment sink.
"""
import stripe

DRY_RUN = True


def human_approval(ticket):
    return input("approve refund %s? [y/N] " % ticket) == "y"


def issue_refund(charge_id, ticket):
    # DECOY D04 — guarded payment: dry-run + human approval before the sink.
    if DRY_RUN:
        print("[dry-run] would refund", charge_id)
        return None
    if not human_approval(ticket):
        raise PermissionError("refund not approved")
    return stripe.Refund.create(charge=charge_id)
