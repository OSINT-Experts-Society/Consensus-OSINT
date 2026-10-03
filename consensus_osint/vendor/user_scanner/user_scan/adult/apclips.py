import re
from urllib.parse import quote, unquote, urljoin, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue
from consensus_osint.core.named_user_contracts import _url
from consensus_osint.vendor.user_scanner.core.impersonate import impersonate_validate
from consensus_osint.vendor.user_scanner.core.result import Result

BASE_URL = "https://apclips.com"


def _link(raw):
    if not isinstance(raw, str) or not raw or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in raw):
        return None
    try:
        return _url(urljoin(BASE_URL, raw))
    except ValueError:
        return None


def _one_text(soup, selector):
    nodes = soup.select(selector)
    return nodes[0].get_text(" ", strip=True) if len(nodes) == 1 else ""


def validate_apclips(user):
    url = BASE_URL + "/" + quote(user, safe="")
    return impersonate_validate(url, lambda response: _result(response, user), show_url=url, allow_redirects=False)


def _result(response, user):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        return Result.error(reason)
    soup = BeautifulSoup(response.text, "html.parser")
    for node in soup.find_all(["script", "style", "template", "noscript"]):
        node.decompose()
    owner_values = [node.get("data-username") for node in soup.select('[data-username]')]
    if any(not isinstance(value, str) or not value for value in owner_values):
        return Result.error("Invalid APClips creator identity")
    owners = {value.casefold() for value in owner_values}
    name = _one_text(soup, "h1.page-modelname")
    if not user or owners != {user.casefold()} or not name:
        return Result.error("No unique matching APClips creator page")
    extra = {"username": user, "name": name, "scope": "APClips creator page; not proof of ownership"}
    if kind := _one_text(soup, '.header-ctlabel'):
        extra["type"] = kind
    identities = {node.get("data-creator-id") for node in soup.select('[data-creator-id]')}
    if len(identities) == 1:
        identity = identities.pop()
        if isinstance(identity, str) and re.fullmatch(r"[0-9]+", identity):
            extra["creator_id"] = identity
    if bio := _one_text(soup, 'div.text-medium.pb-2'):
        extra["bio"] = bio
    reserved = {"username", "name", "scope", "type", "creator_id", "bio", "photosets", "bundles", "categories", "links", "media"}
    stats = {}
    for node in soup.select('div.about-stat'):
        key = _one_text(node, 'span.stat-label').casefold().replace(" ", "_")
        value = _one_text(node, 'span.stat-text')
        if key and value and key not in reserved and not key.startswith("_"):
            stats.setdefault(key, []).append(value)
    extra.update({key: values[0] for key, values in stats.items() if len(values) == 1})
    for section in ("photosets", "bundles"):
        counts = set()
        for link in soup.select('a[href]'):
            if link.get("href", "").casefold() != ("/" + quote(user, safe="") + "/" + section).casefold():
                continue
            previous = link.find_previous_sibling()
            if previous is not None and previous.name == "strong":
                value = previous.get_text(" ", strip=True)
                if re.fullmatch(r"[0-9,]+", value):
                    counts.add(value)
        if len(counts) == 1:
            extra[section] = counts.pop()
    categories = [node.get_text(" ", strip=True) for node in soup.select('a.profile-tag-link')]
    if any(categories):
        extra["categories"] = ", ".join(value for value in categories if value)
    links = []
    for link in soup.select('a.btn.btn-outline-dark.btn-block[target="_blank"]'):
        label = _one_text(link, 'span')
        if label and (href := _link(link.get("href"))):
            links.append(label + ": " + href)
    if links:
        extra["links"] = ", ".join(links)
    media = {}
    prefix = "/ui/img/model/" + quote(user, safe="") + "/"
    for kind, raws in (("avatar", [node.get("src") for node in soup.select('img[src]')]),
                       ("banner", [match[1] for node in soup.select('#page-mast[style]')
                                   for match in re.findall(r"url\((['\"]?)(.*?)\1\)", node.get("style", ""))])):
        urls = set()
        expected = prefix + ("avatar/" if kind == "avatar" else "header/")
        for raw in raws:
            if href := _link(raw):
                parts = urlsplit(href)
                if (parts.scheme == "https" and parts.netloc == "apclips.com"
                        and parts.path.casefold().startswith(expected.casefold())
                        and not any(part in (".", "..") for part in unquote(parts.path).split("/"))):
                    urls.add(href)
        if len(urls) == 1:
            media[kind] = urls.pop()
    return Result.taken(extra=extra, media=media)
