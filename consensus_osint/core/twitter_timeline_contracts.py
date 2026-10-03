"""Matching author evidence in the retained public syndication timeline."""
import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error
from .soundcloud_contracts import _Scripts
from .x_contracts import valid_user


class _TimelineScripts(_Scripts):
    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        if tag == "script":
            values = dict(attrs)
            self.current = ([] if not self.ignored and len(values) == len(attrs) and "src" not in values
                            and values.get("id") == "__NEXT_DATA__" and values.get("type") == "application/json" else None)


def outcome(code, text, query, headers):
    issue, reason = http_issue(code, headers, text)
    if issue is not None:
        return issue, {}, reason
    if not valid_user(query):
        return Status.UNKNOWN, {}, "Invalid X handle"
    try:
        scripts = _TimelineScripts(text).scripts
        if len(scripts) != 1:
            raise ValueError
        root = json.loads(scripts[0], object_pairs_hook=_unique_object)
        props = root["props"]
        page = props["pageProps"]
        context, timeline = page["contextProvider"], page["timeline"]
        if any(not isinstance(node, dict) or has_service_error(node) for node in (root, props, page, context, timeline)):
            raise ValueError
        if context.get("hasResults") is not True:
            raise ValueError
        if "headerProps" in page:
            header = page["headerProps"]
            if not isinstance(header, dict) or not isinstance(header.get("screenName"), str) or header["screenName"].casefold() != query.casefold():
                raise ValueError
        entries = timeline["entries"]
        if not isinstance(entries, list):
            raise ValueError
        authors = []
        for entry in entries:
            content = entry.get("content") if isinstance(entry, dict) else None
            tweet = content.get("tweet") if isinstance(content, dict) else None
            author = tweet.get("user") if isinstance(tweet, dict) else None
            if not isinstance(author, dict) or not isinstance(author.get("screen_name"), str) or author["screen_name"].casefold() != query.casefold():
                continue
            if any(has_service_error(node) for node in (entry, content, tweet, author)):
                raise ValueError
            if type(tweet.get("id")) is not int or tweet["id"] <= 0 or type(author.get("id")) is not int or author["id"] <= 0:
                raise ValueError
            if "id_str" in author and author["id_str"] != str(author["id"]):
                raise ValueError
            authors.append(author)
        if not authors or len({author["id"] for author in authors}) != 1:
            raise ValueError
        fields = {"username": authors[0]["screen_name"], "user_id": authors[0]["id"],
                  "scope": "Author in a public X timeline embed; not proof of current profile availability or ownership"}
        names = [author.get("name") for author in authors]
        if all(isinstance(name, str) and name.strip() for name in names) and len(set(names)) == 1:
            fields["name"] = names[0]
        return Status.FOUND, fields, None
    except (KeyError, TypeError, ValueError):
        return Status.UNKNOWN, {}, "No unambiguous matching author in the syndication timeline"
