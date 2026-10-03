import json
from urllib.parse import quote

from consensus_osint.core.characterai_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_characterai(user: str) -> Result:
    return generic_validate(
        "https://character.ai/api/trpc/social.publicProfile", lambda response: result(response, user),
        params={"input": json.dumps({"json": {"username": user}})},
        show_url=f"https://character.ai/profile/{quote(user, safe='')}", follow_redirects=False,
    )
