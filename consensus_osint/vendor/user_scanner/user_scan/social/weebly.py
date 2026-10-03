import re
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, make_request
from consensus_osint.core.request_templates import subdomain_label

def validate_weebly(user):
    try:
        user = subdomain_label(user)
    except ValueError as exc:
        return Result.skipped(str(exc))
    url = f"https://{user}.weebly.com/"
    
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
        desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        if desc_match:
            extra["description"] = desc_match.group(1).strip()
        extra["_page_metadata_fields"] = ",".join(key for key in ("title", "description") if key in extra)
        return Result.taken(extra=extra, url=url)
        
    return Result.error(f"Unexpected response status: {resp.status_code}")
