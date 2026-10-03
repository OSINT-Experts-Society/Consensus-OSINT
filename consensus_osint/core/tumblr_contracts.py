"""Tumblr blog state evidence; parsing never executes page JavaScript."""
import json
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .named_user_contracts import _text, _url
from .provider_contracts import has_service_error
from .soundcloud_contracts import _Scripts


def valid_user(user):
    return isinstance(user, str) and re.fullmatch(r"[A-Za-z0-9-]{1,32}", user) is not None


class _StateScripts(_Scripts):
    def __init__(self, document):
        self.json_scripts = []
        self.is_json = False
        super().__init__(document)

    def handle_starttag(self, tag, attrs):
        super().handle_starttag(tag, attrs)
        if tag == "script":
            values = dict(attrs)
            self.is_json = (not self.ignored and len(values) == len(attrs) and "src" not in values
                            and values.get("id") == "___INITIAL_STATE___"
                            and (values.get("type") or "").lower() == "application/json")
            if self.is_json:
                self.current = []

    def handle_endtag(self, tag):
        if tag == "script" and self.is_json and self.current is not None:
            self.json_scripts.append("".join(self.current))
            self.current = None
            self.is_json = False
        super().handle_endtag(tag)


def _literal_state_script(script):
    # Historical Tumblr state includes undefined values and RegExp constructors.
    # Treat those non-data values as null; never execute expressions. Quoted
    # strings and comments are consumed intact so their contents are unchanged.
    string = r'"(?:\\.|[^"\\])*"'
    quoted = string + r"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`"
    regexp = r"(?<![\w$.])new\s+RegExp\(\s*" + string + r"(?:\s*,\s*" + string + r")?\s*\)"
    pattern = r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted + r"|(?P<empty>" + regexp + r"|(?<![\w$.])undefined(?![\w$]))"
    return re.sub(pattern, lambda match: "null" if match["empty"] is not None else match[0], script)


def _state(document):
    scripts = _StateScripts(document)
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    states = [decoder.decode(raw) for raw in scripts.json_scripts]
    quoted = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
    pattern = (r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted
               + r"|/(?![*/])(?:\\.|[^/\\\r\n])+/[dgimsuvy]*"
               + r"|(?P<assignment>(?<![\w$.])window\s*(?:\.\s*___INITIAL_STATE___|\[\s*(?:'___INITIAL_STATE___'|\"___INITIAL_STATE___\")\s*\])\s*=)")
    for script in scripts.scripts:
        script = _literal_state_script(script)
        for match in re.finditer(pattern, script):
            if match["assignment"] is None:
                continue
            start = match.end()
            while start < len(script) and script[start].isspace():
                start += 1
            state, end = decoder.raw_decode(script, start)
            tail = script[end:].lstrip()
            if tail and not tail.startswith(";"):
                raise ValueError("Unsupported state assignment")
            states.append(state)
    if len(states) != 1 or not isinstance(states[0], dict) or has_service_error(states[0]):
        raise ValueError("Missing or ambiguous Tumblr state")
    return states[0]


def _find_blog(state, user):
    matches, pending = [], [state]
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, dict):
            if has_service_error(value):
                continue
            blog = value.get("blog")
            if isinstance(blog, dict) and isinstance(blog.get("name"), str) and blog["name"].lower() == user:
                if has_service_error(blog):
                    raise ValueError("Failed blog state")
                if blog not in matches:
                    matches.append(blog)
            pending.extend(value.values())
    return matches[0] if len(matches) == 1 else None


def _page_identity(document, user):
    soup = BeautifulSoup(document, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    urls = [node.get("href") for node in soup.select('link[rel="canonical"]')]
    urls += [node.get("content") for node in soup.select('meta[property="og:url"]')]
    if not urls:
        return False
    for url in urls:
        if not _url(url) or "\\" in url:
            return False
        try:
            parts = urlsplit(url)
            if (parts.scheme != "https" or parts.port not in (None, 443) or parts.query or parts.fragment
                    or not ((parts.hostname == "www.tumblr.com" and parts.path.rstrip("/").lower() == "/" + user)
                            or (parts.hostname == user + ".tumblr.com" and parts.path in ("", "/")))):
                return False
        except ValueError:
            return False
    return True


def result(response, user):
    if not valid_user(user):
        return Result.error("Invalid Tumblr blog name")
    user = user.lower()
    show_url = "https://www.tumblr.com/" + user
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    if not _page_identity(response.text, user):
        return Result.error("No matching Tumblr page identity")
    try:
        blog = _find_blog(_state(response.text), user)
    except (TypeError, ValueError, RecursionError):
        return Result.error("Invalid or ambiguous Tumblr state")
    if not blog:
        return Result.error("No unique matching Tumblr blog")
    extra = {"username": blog["name"], "scope": "Tumblr blog; not proof of account ownership"}
    if title := _text(blog.get("title")):
        extra["title"] = title
    if description := _npf_text(blog.get("descriptionNpf")):
        extra["description"] = description
    if uuid := _text(blog.get("uuid")):
        extra["uuid"] = uuid
    if (url := _url(blog.get("url"))) and url != show_url:
        extra["blog_url"] = url
    if tags := _top_tags(blog.get("topTags")):
        extra["top_tags"] = tags
    for key, target in (("isAdult", "adult"), ("isPasswordProtected", "password_protected"), ("ask", "asks_enabled")):
        if type(blog.get(key)) is bool:
            extra[target] = blog[key]

    media = {}
    if avatar := _largest_avatar(blog.get("avatar")):
        media["avatar"] = avatar
    theme = blog.get("theme")
    if isinstance(theme, dict) and (header := _url(theme.get("headerImage"))):
        media["header"] = header

    return Result.taken(extra=extra, media=media)


def _npf_text(blocks) -> str:
    if not isinstance(blocks, list):
        return ""
    texts = [
        block["text"]
        for block in blocks
        if isinstance(block, dict) and block.get("type") == "text" and _text(block.get("text"))
    ]
    return "\n".join(texts).strip()


def _top_tags(tags) -> str:
    if not isinstance(tags, list):
        return ""
    return ", ".join(tag["tag"] for tag in tags if isinstance(tag, dict) and _text(tag.get("tag")))


def _largest_avatar(avatars) -> str:
    if not isinstance(avatars, list):
        return ""
    sized = [a for a in avatars if isinstance(a, dict) and _url(a.get("url"))
             and type(a.get("width")) is int and a["width"] >= 0]
    if not sized:
        return ""
    return max(sized, key=lambda a: a["width"])["url"]
