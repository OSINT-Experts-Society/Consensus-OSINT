"""LiveJournal embedded journal identity and typed optional fields."""
import json
import re

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error
from .soundcloud_contracts import _Scripts


def canonical(value):
    return value.lower().replace("-", "_") if isinstance(value, str) else None


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    quoted = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
    pattern = (r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted
               + r"|/(?![*/])(?:\\.|[^/\\\r\n])+/[dgimsuvy]*"
               + r"|(?P<assignment>(?<![\w$.])Site\s*\.\s*journal\s*=)")
    journals = []
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    try:
        for script in _Scripts(response.text).scripts:
            for match in re.finditer(pattern, script):
                if match["assignment"] is None:
                    continue
                start = match.end()
                while start < len(script) and script[start].isspace():
                    start += 1
                journal, end = decoder.raw_decode(script, start)
                tail = script[end:].lstrip()
                if not isinstance(journal, dict) or tail and not tail.startswith(";"):
                    return Result.error("Unsupported LiveJournal state assignment")
                journals.append(journal)
    except (TypeError, ValueError):
        return Result.error("Invalid or ambiguous LiveJournal JSON")
    if len(journals) != 1 or not isinstance(journals[0], dict) or has_service_error(journals[0]):
        return Result.error("No unique successful LiveJournal state")
    journal = journals[0]
    name = _text(journal.get("display_username"))
    if not name or canonical(name) != canonical(user):
        return Result.error("LiveJournal state identifies a different journal")
    extra, media = {"name": name}, {}
    if type(journal.get("id")) is int and journal["id"] > 0:
        extra["uid"] = journal["id"]
    if value := _text(journal.get("journal_subtitle")):
        extra["subtitle"] = value
    if value := _url(journal.get("journal_url")):
        extra["journal_url"] = value
    if value := _url(journal.get("userhead_url")):
        media["userhead"] = value
    if type(journal.get("is_paid")) is bool:
        extra["is_paid"] = journal["is_paid"]
    flags = ("is_syndicated", "is_news", "is_personal")
    if all(type(journal.get(key)) is bool for key in flags):
        extra["type"] = "syndicated feed" if journal[flags[0]] else "news" if journal[flags[1]] else "personal" if journal[flags[2]] else "community"
    return Result.taken(extra=extra, media=media)
