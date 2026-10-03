"""Parse Autodiscover routing metadata; never infer mailbox ownership.

The V2 response carries Protocol and Url, as described in Microsoft's Outlook
troubleshooting documentation. Our adapters request Autodiscoverv1. A typed
endpoint response supplies routing information, not an account-existence API.
Reference: https://learn.microsoft.com/en-us/troubleshoot/outlook/message-body/actionable-messages-render-incorrectly
"""
from urllib.parse import urlsplit


def routing_fields(response) -> dict | None:
    if response.status_code != 200:
        return None
    try:
        data = response.json()
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("Protocol") != "Autodiscoverv1":
        return None
    endpoint = data.get("Url")
    if not isinstance(endpoint, str) or any(ch.isspace() or ord(ch) < 32 for ch in endpoint):
        return None
    try:
        parsed = urlsplit(endpoint)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment):
            return None
        _ = parsed.port  # Reject malformed ports before treating this as an endpoint.
    except ValueError:
        return None
    return {"autodiscover_protocol": data["Protocol"], "autodiscover_url": endpoint}
