"""Config-driven gateway factory. The `mode` string comes from request/config
and selects which gateway class handles the charge.
"""
from gateways import DynamicGateway, NoopGateway, StripeGateway

_GATEWAYS = {
    "live": StripeGateway,
    "dynamic": DynamicGateway,
    "test": NoopGateway,
}


def make_gateway(mode):
    return _GATEWAYS[mode]()
