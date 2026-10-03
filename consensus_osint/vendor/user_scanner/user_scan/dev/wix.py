import re
import html
import httpx
from consensus_osint.vendor.user_scanner.core.result import Result
from consensus_osint.vendor.user_scanner.core import orchestrator
from consensus_osint.core.request_templates import subdomain_label

def validate_wix(username: str) -> Result:
    """Validate a username on Wix."""
    try:
        username = subdomain_label(username)
    except ValueError as exc:
        return Result.skipped(str(exc))
    url = f"https://{username}.wix.com"
    show_url = url
    try:
        response = orchestrator.make_request(url, follow_redirects=True)
        response_text = response.text
        
        # Verify status code 200 AND check unique Wix strings in the response body to prevent false positives
        if response.status_code == 200 and "wix" in response_text.lower():
            extra = {}
            title_match = re.search(r"<title>(.*?)</title>", response_text, re.IGNORECASE)
            if title_match:
                extra["title"] = html.unescape(title_match.group(1).strip())
            extra["_page_metadata_fields"] = ",".join(key for key in ("title",) if key in extra)
            return Result.taken(extra=extra, url=show_url)
        elif response.status_code == 404:
            return Result.available(url=show_url)
        return Result.error(f"Unexpected status: {response.status_code}", url=show_url)
    except httpx.ConnectError:
        return Result.error("Connection failed; site availability is unknown", url=show_url)
    except httpx.TimeoutException:
        return Result.error("Connection timed out; site availability is unknown", url=show_url)
    except Exception as e:
        return Result.error(e, url=show_url)
