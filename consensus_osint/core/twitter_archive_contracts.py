"""Wayback availability evidence for Twitter URLs, not current accounts."""
import json
import re
from datetime import datetime
from urllib.parse import quote, unquote, urlencode, urlsplit

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def target(query, tweets):
    return "https://twitter.com/" + quote(query, safe="") + ("/status/*" if tweets else "")


def request_url(query, tweets):
    return "https://archive.org/wayback/available?" + urlencode({"url": target(query, tweets)})


def outcome(code, text, query, headers, tweets):
    issue, reason = http_issue(code, headers, text)
    if issue is not None:
        return issue, {}, reason
    try:
        root = json.loads(text, object_pairs_hook=_unique_object)
        if not isinstance(root, dict) or has_service_error(root):
            raise ValueError
        if "url" in root and root["url"] != target(query, tweets):
            raise ValueError
        snapshots = root["archived_snapshots"]
        if not isinstance(snapshots, dict) or has_service_error(snapshots):
            raise ValueError
        if not snapshots:
            return Status.UNKNOWN, {}, "No accessible snapshot returned; this does not establish whether an account existed"
        closest = snapshots["closest"]
        if not isinstance(closest, dict) or has_service_error(closest):
            raise ValueError
        if closest.get("available") is not True or closest.get("status") != "200":
            raise ValueError
        stamp, raw = closest["timestamp"], closest["url"]
        if not isinstance(stamp, str) or re.fullmatch(r"[0-9]{14}", stamp) is None:
            raise ValueError
        datetime.strptime(stamp, "%Y%m%d%H%M%S")
        if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
            raise ValueError
        parsed = urlsplit(raw)
        prefix = "/web/" + stamp + "/"
        if (parsed.scheme not in ("http", "https") or parsed.netloc != "web.archive.org"
                or parsed.query or parsed.fragment or not parsed.path.startswith(prefix)):
            raise ValueError
        original = urlsplit(parsed.path[len(prefix):])
        if original.scheme not in ("http", "https") or original.netloc not in ("twitter.com", "www.twitter.com"):
            raise ValueError
        path = unquote(original.path).rstrip("/")
        expected = "/" + query
        if tweets:
            if re.fullmatch(re.escape(expected) + r"/status/[1-9][0-9]*", path, re.IGNORECASE) is None:
                raise ValueError
        elif path.casefold() != expected.casefold():
            raise ValueError
        fields = {"snapshot_url": "https://web.archive.org" + parsed.path, "timestamp": stamp,
                  "scope": "Archived URL availability; not proof of account existence, current activity or ownership"}
        return Status.FOUND, fields, None
    except (KeyError, TypeError, ValueError):
        return Status.UNKNOWN, {}, "No valid snapshot bound to the requested Twitter URL"
