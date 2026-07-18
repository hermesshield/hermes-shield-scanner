"""Channel factory. The channel name is read from config; the constructor args
(webhook URL, API key) are environment/config supplied.
"""
from channels import EmailChannel, ShellChannel, SlackChannel

_CHANNELS = {
    "slack": SlackChannel,
    "email": EmailChannel,
    "shell": ShellChannel,
}


def get_channel(name, **kwargs):
    cls = _CHANNELS[name]
    return cls(**kwargs) if kwargs else cls()
