"""Queue consumer. UNTRUSTED INGRESS: each job popped off the queue carries the
target channel name and the message body, both attacker-influenced upstream.
"""
from factory import get_channel


def publish(job, config):
    # job: {"channel": ..., "message": ...} — untrusted
    channel = get_channel(job["channel"], **config.get(job["channel"], {}))
    return channel.send(job["message"])


def consume(queue, config):
    for job in queue:
        publish(job, config)
