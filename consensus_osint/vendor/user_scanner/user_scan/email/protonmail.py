import json

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_protonmail(user: str) -> Result:
    """Check username availability; this does not establish mailbox ownership."""
    if not valid_token(user) or "@" in user:
        return Result.error("Expected a Proton username without a domain or whitespace")
    address = f"{user}@proton.me"

    def process(response):
        issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 409))
        if issue is not None:
            return Result.error(reason)
        try:
            data = json.loads(response.text, object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return Result.error("Invalid or ambiguous Proton response JSON")
        if not isinstance(data, dict) or type(data.get("Code")) is not int:
            return Result.error("No typed Proton availability code")
        code = data["Code"]
        # The retained conflict code can include Proton's human-readable Error.
        checked = dict(data)
        if code == 12106 and isinstance(checked.get("Error"), str):
            checked.pop("Error")
        if has_service_error(checked):
            return Result.error("Contradictory Proton response")
        if "Name" in data and (not isinstance(data["Name"], str) or data["Name"].casefold() != address.casefold()):
            return Result.error("Proton response identifies a different address")
        extra = {"scope": "Username availability; not proof of mailbox existence or ownership", "response_code": code}
        if response.status_code == 409 and code == 12106:
            return Result.taken(extra={**extra, "available": False})
        if response.status_code == 200 and code == 1000:
            return Result.available(extra={**extra, "available": True})
        return Result.error("Unsupported Proton status and availability code combination")

    return generic_validate(
        "https://account.proton.me/api/core/v4/users/available", process,
        show_url="https://account.proton.me", params={"Name": address, "ParseDomain": "1"},
        headers={"x-pm-appversion": "web-mail@6.0.1.3", "Accept": "application/json"}, follow_redirects=False,
    )
