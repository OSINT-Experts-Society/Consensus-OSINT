from urllib.parse import quote

from consensus_osint.core.dailymotion_contracts import result
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate


def validate_dailymotion(user):
    encoded = quote(user, safe="")
    fields = "id,username,screenname,description,avatar_720_url,cover_250_url,followers_total,following_total,videos_total,country,created_time,verified,url"
    return generic_validate(
        f"https://api.dailymotion.com/user/{encoded}", lambda response: result(response, user),
        params={"fields": fields}, headers={"User-Agent": get_random_user_agent(), "Accept": "application/json"},
        show_url=f"https://www.dailymotion.com/{encoded}", follow_redirects=False,
    )
