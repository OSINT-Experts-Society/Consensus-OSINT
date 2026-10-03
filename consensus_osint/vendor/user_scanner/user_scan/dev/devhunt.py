from urllib.parse import quote

from consensus_osint.core.developer_user_contracts import result
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, generic_validate

API_URL = "https://xpdhqqwgprlqmqaqmnyx.supabase.co/rest/v1/profiles"
# DevHunt's public Supabase anon key expires 2033-05-23 04:14:47 UTC.
API_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhwZGhxcXdncHJscW1xYXFtbnl4Iiw"
    "icm9sZSI6ImFub24iLCJpYXQiOjE2ODQ4NTg0ODcsImV4cCI6MjAwMDQzNDQ4N30."
    "fwN6a_NzygrFxhj0GCxGnJJpHv8q8iNEjY1jvhL8Kv0"
)
PROFILE_FIELDS = "id,username,full_name,avatar_url,website_url,headline,about,social_url,updated_at,products(name)"


def validate_devhunt(user: str) -> Result:
    profile_url = f"https://devhunt.org/@{quote(user, safe='')}"
    api_url = f"{API_URL}?username=eq.{quote(user, safe='')}&select={PROFILE_FIELDS}&products.deleted=eq.false"

    return generic_validate(
        api_url,
        lambda response: result(response, "devhunt", user),
        show_url=profile_url,
        headers={"apikey": API_KEY},
        follow_redirects=False,
    )
