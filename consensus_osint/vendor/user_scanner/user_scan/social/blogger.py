import re
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, make_request
from consensus_osint.core.request_templates import subdomain_label

def validate_blogger(user):
    try:
        user = subdomain_label(user)
    except ValueError as exc:
        return Result.skipped(str(exc))
    url = f"https://{user}.blogspot.com/"
    
    headers = {
        "User-Agent": get_random_user_agent(),
    }
    
    resp = make_request(url, headers=headers, http2=True, follow_redirects=True)
    if resp.status_code == 404:
        return Result.available(url=url)
    elif resp.status_code == 200:
        extra = {}
        title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
        if title_match:
            extra["title"] = title_match.group(1).strip()
        extra["_page_metadata_fields"] = ",".join(key for key in ("title",) if key in extra)
        return Result.taken(extra=extra, url=url)
        
    return Result.error(f"Unexpected response status: {resp.status_code}")
