"""Payment gateway implementations, selected by a factory from config.
StripeGateway performs a real charge; DynamicGateway resolves the operation
name at runtime; NoopGateway is a benign test double.
"""
import stripe


class StripeGateway:
    def charge(self, amount, token):
        # PLANTED S07 — real money movement: stripe.Charge.create, selected via
        # the config-driven factory (make_gateway). Static SHOULD catch this.
        return stripe.Charge.create(amount=amount, currency="usd", source=token)


class DynamicGateway:
    def __init__(self):
        self.client = stripe

    def charge(self, amount, token, action="Charge"):
        # PLANTED S08 — the Stripe resource is chosen by an attacker-influenced
        # `action` string, bound via getattr into a local, then invoked. No
        # literal .create call is written.
        resource = getattr(self.client, action)
        creator = getattr(resource, "create")
        return creator(amount=amount, currency="usd", source=token)


class NoopGateway:
    def charge(self, amount, token):
        # DECOY D03 — benign test double, no capability.
        return {"status": "noop", "amount": amount}
