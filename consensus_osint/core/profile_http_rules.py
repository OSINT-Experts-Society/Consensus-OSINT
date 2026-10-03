"""HTTP preflight scope for exact shipped legacy profile rules."""
import hashlib
import json
from urllib.parse import unquote, urljoin, urlsplit

_HASHES = {
    "bdsmsingles": "659ee31400ffb7832a0942996ab8e8ab2c6f2473e2fe5adf2ac8569994884449",
    "mssg_me": "abfa0a11b4321fa7f43827af5662676df0625e03d51b9c6a1a02a6684aead02d",
    "hamaha": "5012d3b4ce680cbace298a4d8d0f0556f7cdd87defb7c61f80e52163735ba435",
    "amazon": "4b1a7de1a610f27ebc6d95e8474253a2fa91e44f5aa4ae9fadf29aba837264d3",
}


def shipped_rule(entry):
    expected = _HASHES.get(entry.get("id"))
    if expected is None:
        return False
    keys = ("id", "kind", "url", "check_url", "method", "headers", "payload", "follow_redirects",
            "detect", "extract", "form", "impersonate", "source", "replaces")
    encoded = json.dumps({key: entry.get(key) for key in keys}, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest() == expected


# The shipped markers are a title element, an element id and an author-name hook.
# None is account evidence when it occurs only inside a style sheet, and the two
# markup markers are not evidence inside a script string either.
_INERT = {"bdsmsingles": ("script", "style"), "hamaha": ("script", "style"), "amazon": ("style",)}
# Amazon destinations that are demonstrably not the requested author page.
_NOT_AN_AUTHOR = ("/ap/", "/errors/", "/gp/help/", "/gp/browse")


def live_text(kind, text):
    """The response with the elements that cannot carry this rule's marker masked."""
    from .html_evidence import mask_elements

    return mask_elements(text, _INERT.get(kind, ()))


def redirect_target(kind, current, location, query=None):
    """Retain Amazon canonical redirects without accepting foreign pages."""
    if kind != "amazon" or not isinstance(location, str) or not location:
        return None
    if any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in location):
        return None
    try:
        target = urljoin(current, location)
        parsed = urlsplit(target)
        if (parsed.scheme == "https" and parsed.hostname in ("amazon.com", "www.amazon.com")
                and parsed.port in (None, 443) and parsed.username is None and parsed.password is None):
            path = unquote(parsed.path).rstrip("/").lower()
            author = path[len("/author/"):] if path.startswith("/author/") else None
            # Another author's address, the home page, sign-in and error pages are
            # other pages; a store-front address reached from this request is kept.
            if (not path or path.startswith(_NOT_AN_AUTHOR)
                    or (author is not None and query is not None and author != query.strip().lower())):
                return None
            return target
    except ValueError:
        pass
    return None
