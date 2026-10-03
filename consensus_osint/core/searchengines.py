"""Search-engine username reconnaissance.

Ported from *marple* (https://github.com/soxoj/marple) by Soxoj.
Original licence: MIT.  Modified for Consensus: rewritten on top of Consensus's
async :class:`~consensus_osint.core.http.Http` layer (httpx / curl_cffi) and the
unified :class:`~consensus_osint.core.models.Finding` model; keyless engines
only, plus optional Yandex XML when API keys are configured.

MIT License

Copyright (c) 2021 soxoj
Copyright (c) 2024 Consensus contributors (modifications)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

The original notice is also retained in licenses/marple-LICENSE.txt; see
THIRD_PARTY_NOTICES.txt for the reviewed source revision and adaptation scope.

Purpose: collect links to profiles / mentions of a username via web search
engines, decode each engine's redirect wrapper, de-duplicate, rank by a
"junk score" (marple's idea: the less junk, the more likely a real profile)
and expose helpers to convert results into Findings and to mine new handle
candidates for recursion.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import re
from urllib.parse import parse_qs, quote_plus, unquote, urlparse, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

from .config import get_key
from .errors import detect_error_page
from .http import Http, random_user_agent
from .models import Finding, Status, redact_options

log = logging.getLogger("consensus.searchengines")

try:  # Normal core installs include HTML parsing; handle incomplete installs.
    from bs4 import BeautifulSoup  # type: ignore

    _HAVE_BS4 = True
except Exception:  # noqa: BLE001  pragma: no cover
    _HAVE_BS4 = False


# ---------------------------------------------------------------------------
# scoring / classification constants
# ---------------------------------------------------------------------------
# marple's boundary symbols: index in this string == how "junky" a character
# adjacent to the username is (a '/' boundary is best, a '-' worst).
_USERNAME_MARKS = "/.~=?&      -"

# hosts / path fragments that are almost never a personal profile page
_JUNK_PATTERNS = [
    "pinterest.com/pin/",
    "pinterest.",
    "facebook.com/photo",
    "facebook.com/photo.php",
    "facebook.com/media",
    "/search?q=",
    "/search?p=",
    "google.com/search",
    "books.google.",
    "translate.google.",
    "webcache.googleusercontent.com",
    "youtube.com/watch",
    "youtube.com/results",
    "amazon.",
    "ebay.",
    "/imgres",
    "bing.com/images",
    "duckduckgo.com/y.js",
]

# de-dup + never-useful link fragments (marple links_blacklist)
_LINK_BLACKLIST = ["books.google.ru", "/search?q="]

# query params that are pure tracking noise (marple junk_regexps)
_JUNK_PARAM_RE = re.compile(r"(?:[?&](?:ref_src|via|utm_[a-z]+|fbclid|gclid)=[^&]*)", re.I)

_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")

ALL_ENGINES = ["duckduckgo", "bing", "yahoo", "startpage", "yandex", "google"]
# engines that run without any API key
DEFAULT_ENGINES = ["duckduckgo", "bing", "yahoo", "startpage", "google"]


class SearchResults(list[dict]):
    """Ranked links with separate engine failures; normal list callers still work.

    Pass this object directly to :func:`to_findings` to retain the issues in
    reports. An empty list of links alone never establishes account absence.
    """

    def __init__(self, links=(), *, issues=()):
        super().__init__(links)
        self.issues: list[Finding] = list(issues)


def _issue(out: SearchResults, username: str, engine: str, status: Status,
           detail: str, http_status: int | None = None) -> None:
    if any(f.status is status and f.error == detail and f.http_status == http_status for f in out.issues):
        return
    names = {"duckduckgo": "DuckDuckGo", "bing": "Bing", "yahoo": "Yahoo",
             "startpage": "Startpage", "yandex": "Yandex", "google": "Google"}
    out.issues.append(Finding(
        query=username, query_type="username", site=names.get(engine, engine) + " search",
        site_id="se-engine-" + engine, status=status, category="search",
        source="search-engines", method=engine, http_status=http_status,
        error=detail, extra={"_engine": engine, "_links_collected": len(out)},
    ))


def _page_ok(out: SearchResults, username: str, engine: str, resp) -> bool:
    """A successful transport alone is not a usable search response."""
    code = resp.status if resp else None
    if not resp or not resp.ok:
        status, detail = Status.ERROR, "The search request failed or timed out."
    elif code == 429:
        status, detail = Status.RATE_LIMITED, "The search engine limited requests (HTTP 429)."
    elif code in (401, 403):
        status, detail = Status.BLOCKED, f"The search engine requires access or authentication (HTTP {code})."
    elif code >= 400:
        status, detail = Status.ERROR, f"The search endpoint returned HTTP {code}."
    elif code != 200:
        status, detail = Status.UNKNOWN, f"The search endpoint returned an unexpected HTTP {code}."
    elif (error := detect_error_page(resp.text or "", code)) is not None:
        status, detail = Status.BLOCKED, f"The search page could not be used: {error}."
    else:
        return True
    _issue(out, username, engine, status, detail, code)
    return False


def _unreadable(out: SearchResults, username: str, engine: str, code: int) -> None:
    _issue(out, username, engine, Status.UNKNOWN,
           "No usable result links were recognised on this page. It may be empty or use an unsupported layout; "
           "this does not establish that the username has no profiles.", code)


def _decode_result(out: SearchResults, username: str, engine: str, decoder, href: str, code: int) -> str | None:
    try:
        return decoder(href)
    except ValueError:
        _issue(out, username, engine, Status.UNKNOWN,
               "A result link contained an unreadable redirect wrapper. Other usable links have been retained.", code)
        return None


def _html_headers() -> dict:
    return {
        "User-Agent": random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------
def _clean_url(url: str) -> str:
    """Remove known tracking parameters without rewriting the target resource."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    parameters = [p for p in parts.query.split("&")
                  if p and not _JUNK_PARAM_RE.match("?" + p)]
    return urlunsplit(parts._replace(query="&".join(parameters)))


def _dedup_key(url: str) -> str:
    # Paths, parameters, fragments and trailing slashes can identify distinct
    # resources. HTTP/HTTPS equivalence also needs redirect evidence we lack.
    try:
        parts = urlsplit(_clean_url(url))
        return urlunsplit(parts._replace(scheme=parts.scheme.lower(), netloc=parts.netloc.lower()))
    except ValueError:
        return url


def _host(url: str) -> str:
    try:
        h = urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        h = ""
    return h[4:] if h.startswith("www.") else h


def username_in_url(url: str, username: str) -> bool:
    return username.lower() in (url or "").lower()


def link_junk_score(url: str, username: str) -> float:
    """Lower == more likely a genuine ``username`` profile page (0 is ideal).

    Follows marple's idea: penalise (a) links whose path does not contain the
    username, (b) the username sitting deep in the URL or behind "junky"
    boundary characters, (c) common junk hosts (pinterest pins, facebook photo
    pages, search-result pages ...) and (d) very long URLs.
    """
    u = (url or "").lower()
    name = username.lower()
    parsed = urlparse(u)
    path = parsed.path or ""

    score = 0.0

    if name not in u:
        # Cannot tie the link to the username at all -> heavily penalised.
        score += 100.0
    else:
        idx = u.index(name)
        # username appearing deep in the string is worse (marple: index * 3)
        score += idx * 0.3
        left = u[idx - 1] if idx > 0 else ""
        right_i = idx + len(name)
        right = u[right_i] if right_i < len(u) else ""
        sym_score = sum(_USERNAME_MARKS.index(c) for c in (left + right) if c in _USERNAME_MARKS)
        score += sym_score * 1.5

    # username should live in the *path*, not only the host or query string
    if name and name not in path:
        score += 20.0

    for junk in _JUNK_PATTERNS:
        if junk in u:
            score += 50.0
            break

    # length of the path portion (query stripped) — long URLs are junkier
    base_len = len(u.split("?")[0])
    if base_len > 60:
        score += (base_len - 60) * 0.5

    return round(score, 2)


# ---------------------------------------------------------------------------
# redirect decoders
# ---------------------------------------------------------------------------
def _decode_uddg(href: str) -> str | None:
    """DuckDuckGo wraps links as //duckduckgo.com/l/?uddg=<encoded>&rut=..."""
    if not href:
        return None
    if "uddg=" in href:
        query = urlparse(href).query or href.split("?", 1)[-1]
        params = parse_qs(query)
        if params.get("uddg"):
            return params["uddg"][0]  # parse_qs already decoded the wrapper layer.
    if href.startswith("http"):
        return href
    return None


def _b64decode(data: str) -> str | None:
    try:
        data = data.replace("-", "+").replace("_", "/")
        data += "=" * (-len(data) % 4)
        return base64.b64decode(data).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


def _decode_bing(href: str) -> str | None:
    """Bing sometimes wraps links as .../ck/a?...&u=a1<base64url>&..."""
    if not href:
        return None
    if "/ck/a" in href and "u=" in href:
        u = parse_qs(urlparse(href).query).get("u", [""])[0]
        if u.startswith("a1"):
            decoded = _b64decode(u[2:])
            if decoded and decoded.startswith("http"):
                return decoded
    if href.startswith("http"):
        return href
    return None


def _decode_ru(href: str) -> str | None:
    """Yahoo wraps links as https://r.search.yahoo.com/.../RU=<encoded>/RK=..."""
    if not href:
        return None
    m = re.search(r"RU=([^/]+)", href)
    if m:
        real = unquote(m.group(1))
        if real.startswith("http"):
            return real
    if href.startswith("http") and "search.yahoo.com" not in href and "r.search.yahoo" not in href:
        return href
    return None


def _decode_google(href: str) -> str | None:
    if not href:
        return None
    if href.startswith("/url?"):
        params = parse_qs(urlparse(href).query)
        q = params.get("q") or params.get("url")
        return q[0] if q else None
    if href.startswith("http"):
        return href
    return None


# ---------------------------------------------------------------------------
# per-engine parsers (each returns a list of {url,title,engine})
# ---------------------------------------------------------------------------
async def _engine_duckduckgo(username: str, query: str, http: Http, pages: int) -> list[dict]:
    out = SearchResults()
    seen: set[str] = set()
    for page in range(max(1, pages)):
        resp = await http.request(
            "POST",
            "https://html.duckduckgo.com/html/",
            data={"q": query, "s": str(page * 30), "kl": "wt-wt"},
            headers=_html_headers(),
        )
        if not _page_ok(out, username, "duckduckgo", resp):
            break
        soup = BeautifulSoup(resp.text, "html.parser")
        anchors = soup.select("a.result__a")
        if not anchors:
            _unreadable(out, username, "duckduckgo", resp.status)
            break
        new = 0
        parsed_links = 0
        for a in anchors:
            real = _decode_result(out, username, "duckduckgo", _decode_uddg, a.get("href", ""), resp.status)
            if not real:
                continue
            parsed_links += 1
            key = _dedup_key(real)
            if key in seen:
                continue
            seen.add(key)
            new += 1
            out.append({"url": _clean_url(real), "title": a.get_text(" ", strip=True), "engine": "duckduckgo"})
        if parsed_links == 0:
            _unreadable(out, username, "duckduckgo", resp.status)
            break
        if new == 0:
            break
    return out


async def _engine_bing(username: str, query: str, http: Http, pages: int) -> list[dict]:
    out = SearchResults()
    seen: set[str] = set()
    for page in range(max(1, pages)):
        first = page * 10 + 1
        url = f"https://www.bing.com/search?q={quote_plus(query)}&first={first}"
        resp = await http.get(url, headers=_html_headers())
        if not _page_ok(out, username, "bing", resp):
            break
        soup = BeautifulSoup(resp.text, "html.parser")
        anchors = soup.select("li.b_algo h2 a[href]") or soup.select("h2 a[href]")
        if not anchors:
            _unreadable(out, username, "bing", resp.status)
            break
        new = 0
        parsed_links = 0
        for a in anchors:
            real = _decode_result(out, username, "bing", _decode_bing, a.get("href", ""), resp.status)
            if not real:
                continue
            parsed_links += 1
            key = _dedup_key(real)
            if key in seen:
                continue
            seen.add(key)
            new += 1
            out.append({"url": _clean_url(real), "title": a.get_text(" ", strip=True), "engine": "bing"})
        if parsed_links == 0:
            _unreadable(out, username, "bing", resp.status)
            break
        if new == 0:
            break
    return out


async def _engine_yahoo(username: str, query: str, http: Http, pages: int) -> list[dict]:
    out = SearchResults()
    seen: set[str] = set()
    for page in range(max(1, pages)):
        b = page * 10 + 1
        url = f"https://search.yahoo.com/search?p={quote_plus(query)}&b={b}"
        resp = await http.get(url, headers=_html_headers())
        if not _page_ok(out, username, "yahoo", resp):
            break
        soup = BeautifulSoup(resp.text, "html.parser")
        anchors = soup.select("h3 a[href]") or soup.select('a[href*="RU="]')
        if not anchors:
            _unreadable(out, username, "yahoo", resp.status)
            break
        new = 0
        parsed_links = 0
        for a in anchors:
            real = _decode_ru(a.get("href", ""))
            if not real:
                continue
            parsed_links += 1
            key = _dedup_key(real)
            if key in seen:
                continue
            seen.add(key)
            new += 1
            out.append({"url": _clean_url(real), "title": a.get_text(" ", strip=True), "engine": "yahoo"})
        if parsed_links == 0:
            _unreadable(out, username, "yahoo", resp.status)
            break
        if new == 0:
            break
    return out


async def _engine_startpage(username: str, query: str, http: Http, pages: int) -> list[dict]:
    # Startpage frequently blocks automated GETs (token / captcha) — one polite
    # attempt, and whatever we can parse is returned.
    out = SearchResults()
    seen: set[str] = set()
    url = f"https://www.startpage.com/do/search?q={quote_plus(query)}"
    resp = await http.get(url, headers=_html_headers())
    if not _page_ok(out, username, "startpage", resp):
        return out
    soup = BeautifulSoup(resp.text, "html.parser")
    anchors = (
        soup.select("a.w-gl__result-title")
        or soup.select("a.result-link")
        or soup.select("a.result-title")
    )
    for a in anchors:
        href = a.get("href", "")
        if not href.startswith("http"):
            continue
        key = _dedup_key(href)
        if key in seen:
            continue
        seen.add(key)
        out.append({"url": _clean_url(href), "title": a.get_text(" ", strip=True), "engine": "startpage"})
    if not out:
        _unreadable(out, username, "startpage", resp.status)
    return out


async def _engine_yandex(username: str, query: str, http: Http, pages: int) -> list[dict]:
    """Yandex free XML API — only usable when yandex_user / yandex_key are set."""
    user = get_key("yandex_user")
    key = get_key("yandex_key")
    out = SearchResults()
    if not user or not key:
        _issue(out, username, "yandex", Status.SKIPPED, "Yandex requires yandex_user and yandex_key settings.")
        return out
    seen: set[str] = set()
    for page in range(max(1, pages)):
        url = (
            f"https://yandex.com/search/xml?user={quote_plus(user)}&key={quote_plus(key)}"
            f"&query={quote_plus(query)}&l10n=en&sortby=rlv&filter=none&page={page}"
        )
        resp = await http.get(url, headers=_html_headers())
        if not _page_ok(out, username, "yandex", resp):
            break
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError:
            _unreadable(out, username, "yandex", resp.status)
            break
        if root.find(".//error") is not None:
            _issue(out, username, "yandex", Status.ERROR, "Yandex returned a provider error instead of search results.", resp.status)
            break
        if root.find(".//doc") is None:
            _unreadable(out, username, "yandex", resp.status)
            break
        new = 0
        parsed_links = 0
        for doc in root.iter("doc"):
            u = doc.findtext("url") or ""
            title = "".join(doc.itertext()).strip() if doc.find("title") is None else _xml_text(doc.find("title"))
            if not u:
                continue
            parsed_links += 1
            k = _dedup_key(u)
            if k in seen:
                continue
            seen.add(k)
            new += 1
            out.append({"url": _clean_url(u), "title": title or u, "engine": "yandex"})
        if parsed_links == 0:
            _unreadable(out, username, "yandex", resp.status)
            break
        if new == 0:
            break
    return out


def _xml_text(el) -> str:
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


async def _engine_google(username: str, query: str, http: Http, pages: int) -> list[dict]:
    """Single impersonated attempt; keep challenges as inconclusive evidence."""
    out = SearchResults()
    seen: set[str] = set()
    url = f"https://www.google.com/search?q={quote_plus(query)}&num=20&hl=en"
    resp = await http.get(url, headers=_html_headers(), impersonate=True)
    if not _page_ok(out, username, "google", resp):
        return out
    low = (resp.text or "").lower()
    if "unusual traffic" in low or "/sorry/" in low or 'id="gs_captcha_f"' in low or "captcha" in low[:5000]:
        _issue(out, username, "google", Status.BLOCKED, "Google returned a captcha or unusual-traffic page.", resp.status)
        return out
    soup = BeautifulSoup(resp.text, "html.parser")
    for h3 in soup.select("h3"):
        a = h3.find_parent("a")
        if not a:
            continue
        real = _decode_google(a.get("href", ""))
        if not real or not real.startswith("http") or "google." in (_host(real) or ""):
            continue
        key = _dedup_key(real)
        if key in seen:
            continue
        seen.add(key)
        out.append({"url": _clean_url(real), "title": h3.get_text(" ", strip=True), "engine": "google"})
    if not out:
        _unreadable(out, username, "google", resp.status)
    return out


_ENGINE_FUNCS = {
    "duckduckgo": _engine_duckduckgo,
    "bing": _engine_bing,
    "yahoo": _engine_yahoo,
    "startpage": _engine_startpage,
    "yandex": _engine_yandex,
    "google": _engine_google,
}


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------
def _valid_result_url(url) -> bool:
    if not isinstance(url, str) or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        return False
    try:
        parsed = urlsplit(url)
        _ = parsed.port
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except ValueError:
        return False


async def _run_engine(name, fn, username, query, http, pages) -> list[dict]:
    out = SearchResults()
    if name != "yandex" and not _HAVE_BS4:
        _issue(out, username, name, Status.SKIPPED,
               "HTML search parsing requires beautifulsoup4; repair the Consensus core installation.")
        return out
    try:
        group = await fn(username, query, http, pages)
        out = SearchResults((r for r in group if _valid_result_url(r.get("url"))),
                            issues=getattr(group, "issues", ()))
        if len(out) != len(group):
            _issue(out, username, name, Status.UNKNOWN,
                   "Some result links were malformed and could not be used. Any usable links have been retained.")
        return out
    except Exception as exc:  # noqa: BLE001 - never let one engine kill the run
        log.warning("search engine %s failed: %s", name, redact_options({"error": str(exc)})["error"])
        log.debug("engine failure", exc_info=True)
        _issue(out, username, name, Status.ERROR, "The search parser failed unexpectedly; no conclusion is available.")
        return out


async def search_username(
    username: str,
    http: Http,
    *,
    engines: list[str] | None = None,
    pages: int = 2,
    quoted: bool = True,
) -> SearchResults:
    """Search ``username`` across keyless web engines and rank the results.

    Returns de-duplicated dicts sorted by ``junk_score`` (ascending, best
    first)::

        {"url", "title", "engine", "username_in_url": bool, "junk_score": float}

    ``results.issues`` contains engine failures, skips and unrecognised pages.
    It is retained by ``to_findings``; copying only the links loses this context.
    """
    if not isinstance(username, str) or not username.strip():
        return SearchResults()
    if type(pages) is not int or not 1 <= pages <= 20:
        raise ValueError("search pages must be an integer from 1 to 20")
    requested = list(dict.fromkeys(engines)) if engines is not None else list(DEFAULT_ENGINES)
    query = f'"{username}"' if quoted else username

    tasks = []
    raw = SearchResults()
    for name in requested:
        fn = _ENGINE_FUNCS.get(name)
        if fn is None:
            _issue(raw, username, name, Status.SKIPPED, "This search engine name is not supported.")
            continue
        tasks.append(_run_engine(name, fn, username, query, http, pages))

    for group in await asyncio.gather(*tasks, return_exceptions=False):
        raw.extend(group)
        raw.issues.extend(getattr(group, "issues", ()))

    # de-duplicate (across engines) and drop blacklisted links
    seen: dict[str, dict] = {}
    for r in raw:
        url = r.get("url") or ""
        if any(b in url.lower() for b in _LINK_BLACKLIST):
            continue
        key = _dedup_key(url)
        r = {
            "url": url,
            "title": (r.get("title") or "").strip(),
            "engine": r.get("engine", ""),
            "username_in_url": username_in_url(url, username),
            "junk_score": link_junk_score(url, username),
        }
        if key not in seen or r["junk_score"] < seen[key]["junk_score"]:
            seen[key] = r

    results = sorted(seen.values(), key=lambda x: x["junk_score"])
    return SearchResults(results, issues=raw.issues)


def to_findings(username: str, results: list[dict]) -> list[Finding]:
    """Map ranked results to Findings.

    A link with the username in its URL is a positive lead (``FOUND``); the
    rest are recorded as ``UNKNOWN`` mentions. Engine issues are appended as
    separate findings so failures are not mistaken for absent profiles.
    """
    findings: list[Finding] = []
    for r in results:
        url = r.get("url") or ""
        host = _host(url) or "search"
        # A query parameter or a substring of another handle is not a profile lead.
        in_url = unquote(_last_segment(url) or "").lstrip("@").lower() == username.lower()
        findings.append(
            Finding(
                query=username,
                query_type="username",
                site=host,
                site_id="se-" + host,
                status=Status.FOUND if in_url else Status.UNKNOWN,
                url=url,
                category="search",
                source="search-engines",
                method=r.get("engine"),
                confidence=0.5,
                extra={
                    "title": r.get("title", ""),
                    "engine": r.get("engine", ""),
                    "junk_score": r.get("junk_score"),
                    "username_in_url": in_url,
                },
            )
        )
    return findings + list(getattr(results, "issues", ()))


def _last_segment(url: str) -> str | None:
    try:
        path = urlparse(url).path
    except Exception:  # noqa: BLE001
        return None
    parts = [p for p in path.split("/") if p]
    return parts[-1] if parts else None


def link_username_candidates(results: list[dict], username: str | None = None) -> set[str]:
    """Mine probable handles from result URL paths for recursion.

    Takes the last path segment of each URL and accepts only handles with
    the same case-folded, digit-stripped stem as the supplied original username.
    Without that original identifier no recursion candidates are returned.
    """
    segments: list[str] = []
    for r in results:
        seg = _last_segment(r.get("url") or "")
        if seg and _CANDIDATE_RE.match(seg):
            segments.append(seg)

    def stem_of(s: str) -> str:
        return re.sub(r"\d+$", "", s.lower())

    if username is None:
        return set()  # unrelated result sets cannot authorize new identity pivots
    dominant = stem_of(username)
    if len(dominant) < 3:
        return set()

    return {s for s in segments if stem_of(s) == dominant}
