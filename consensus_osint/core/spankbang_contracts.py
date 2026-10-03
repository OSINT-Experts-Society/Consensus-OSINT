"""SpankBang profile evidence and handle-bound optional metadata."""
import re
from urllib.parse import unquote, urljoin, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.vendor.user_scanner.core.result import Result

from .mailbox_contracts import http_issue
from .named_user_contracts import _url
from .soundcloud_contracts import _Scripts


def _profile_ids(document):
    # Skip comments, quoted examples and regex literals before reading the
    # retained numeric analytics assignment. No JavaScript is executed.
    quoted = r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`"
    pattern = (r"//[^\n]*|/\*[\s\S]*?\*/|" + quoted
               + r"|/(?![*/])(?:\\.|[^/\\\r\n])+/[dgimsuvy]*"
               + r"|(?P<assignment>(?<![\w$.])ana_profile_id\s*=\s*(['\"])([0-9]+)\2\s*(?=;|$))")
    values = []
    for script in _Scripts(document).scripts:
        for match in re.finditer(pattern, script):
            if match["assignment"] is not None:
                values.append(match[3])
    return values


def _link(raw):
    if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
        return None
    try:
        return _url(urljoin("https://spankbang.com", raw))
    except ValueError:
        return None


def result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    titles, names = soup.select('title'), soup.select('h1.profile_name')
    if len(titles) != 1 or len(names) != 1 or not user:
        return Result.error("No unique active SpankBang profile title and heading")
    title, name = titles[0].get_text(" ", strip=True), names[0].get_text(" ", strip=True)
    if not name or re.fullmatch(re.escape(user) + r" Profile(?: .*)? @ SpankBang", title, re.IGNORECASE) is None:
        return Result.error("SpankBang profile title does not match the requested handle")
    extra, media = {"username": user, "name": name}, {}
    identities = _profile_ids(response.text)
    if len(identities) == 1:
        extra["user_id"] = identities[0]
    for selector, key in (('span.gender', 'gender'), ('span.age', 'age')):
        nodes = soup.select(selector)
        if len(nodes) == 1 and (value := nodes[0].get_text(" ", strip=True)):
            if key != "age" or re.fullmatch(r"[0-9]+", value):
                extra[key] = value
    flags = soup.select('img.flag[src]')
    if len(flags) == 1 and (flag := _link(flags[0].get("src"))):
        country = re.search(r"/Flags/([A-Za-z]{2})\.png$", urlsplit(flag).path, re.IGNORECASE)
        if country:
            extra["country"] = country[1].upper()
    avatars = soup.select('img.avatar[src]')
    if len(avatars) == 1 and (avatar := _link(avatars[0].get("src"))):
        media["avatar"] = avatar
    stats = {}
    reserved = {"username", "name", "user_id", "gender", "age", "country", "media", "scope"}
    prefix = "/profile/" + user + "/"
    for node in soup.select('a[href]'):
        link = _link(node.get("href"))
        if not link:
            continue
        parsed = urlsplit(link)
        path = unquote(parsed.path)
        if parsed.netloc != "spankbang.com" or parsed.query or parsed.fragment or not path.casefold().startswith(prefix.casefold()):
            continue
        key = path[len(prefix):].casefold()
        counts = node.select('span')
        if not re.fullmatch(r"[a-z_]+", key) or key in reserved or key.startswith("_") or len(counts) != 1:
            continue
        value = counts[0].get_text(" ", strip=True)
        if re.fullmatch(r"[0-9]+(?:[.,][0-9]+)*[KMkm]?", value):
            stats.setdefault(key, []).append(value)
    extra.update({key: values[0] for key, values in stats.items() if len(values) == 1})
    return Result.taken(extra=extra, media=media)
