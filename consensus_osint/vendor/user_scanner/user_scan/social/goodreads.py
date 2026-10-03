import re
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import Result, make_request

def validate_goodreads(user):
    url = f"https://www.goodreads.com/{user}"
    
    headers = {
        "User-Agent": get_random_user_agent(),
    }
    
    resp = make_request(url, headers=headers, http2=True, follow_redirects=True)
    final_url = str(resp.url)
    if resp.status_code == 404:
        return Result.available(url=final_url)
    elif resp.status_code == 200:
        extra = {}
        title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE)
        if title_match:
            extra["title"] = title_match.group(1).strip()
        name_match = re.search(r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        if name_match:
            extra["name"] = name_match.group(1).replace(' (', '').strip()
        extra["_page_metadata_fields"] = ",".join(key for key in ("title",) if key in extra)
        return Result.taken(extra=extra, url=final_url)
        
    return Result.error(f"Unexpected response status: {resp.status_code}")
