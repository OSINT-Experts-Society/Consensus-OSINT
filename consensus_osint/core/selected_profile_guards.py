"""Response and identity guards around selected upstream metadata extractors."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

import httpx
from bs4 import BeautifulSoup, Comment

from ..vendor.user_scanner.core.result import Result
from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .provider_contracts import has_service_error

PROFILE_TEMPLATES = {
    "community.comicvine": "https://comicvine.gamespot.com/profile/{username}/",
    "creative.artbreeder": "https://www.artbreeder.com/{username}",
    "creative.creativemarket": "https://creativemarket.com/users/{username}",
    "gaming.boardgamegeek": "https://boardgamegeek.com/profile/{username}",
    "music.metalarchives": "https://www.metal-archives.com/users/{username}",
    "social.animeplanet": "https://www.anime-planet.com/users/{username}",
    "social.librarything": "https://www.librarything.com/profile/{username}",
    "dev.boot_dev": "https://boot.dev/u/{username}",
    "creator.cameo": "https://www.cameo.com/{username}",
    "creator.gumroad": "https://{username}.gumroad.com/",
    "creator.indiegogo": "https://www.indiegogo.com/en/profile/{username}",
    "creator.kickstarter": "https://www.kickstarter.com/profile/{username}",
    "creator.payhip": "https://payhip.com/{username}",
    "creator.rumble": "https://rumble.com/user/{username}",
    "creator.wisio": "https://www.wisio.com/{username}",
    "gaming.medal": "https://medal.tv/u/{username}",
    "gaming.stackb": "https://stackb.net/@{username}",
    "other.weblancer": "https://www.weblancer.net/users/{username}/",
    "creative.fredmiranda": "https://www.fredmiranda.com/forum/viewprofile.php?Action=viewprofile&username={username}",
    "social.mssg_me": "https://mssg.me/{username}",
}


def declared_profile(func):
    prefix = "consensus_osint.vendor.user_scanner.user_scan."
    module = getattr(func, "__module__", "")
    return PROFILE_TEMPLATES.get(module[len(prefix) :]) if module.startswith(prefix) else None


def same_selected_profile(module, site):
    templates = {"us-user-" + key.replace(".", "-"): value for key, value in PROFILE_TEMPLATES.items()}
    templates["rule-mssg_me"] = "https://mssg.me/{username}"
    expected = templates.get(module.id)
    source = "rules" if module.id == "rule-mssg_me" else "user-scanner"
    if (module.id == 'us-user-social-animeplanet' and module.kind == 'username'
            and module.source == 'user-scanner' and module.url_main == expected
            and site.id == 'anime-planet' and site.id_type == 'username'
            and site.url == expected and site.url_probe == 'https://www.anime-planet.com/api/validation/username'
            and site.method == 'POST' and site.payload == '{"username":"{username}"}'
            and site.headers == {'Content-Type': 'application/json'} and not site.strip_chars):
        # This exact existing availability route checks the same handle. Prefer
        # its accepted public-profile implementation for actual profile fields.
        return True
    if (
        not expected
        or module.url_main != expected
        or module.kind != "username"
        or module.source != source
        or site.id_type != "username"
        or site.method != "GET"
        or site.payload
        or site.strip_chars
        or any(k.lower() not in {"user-agent", "accept", "accept-language"} for k in site.headers)
    ):
        return False
    urls = {expected.rstrip("/")}
    if module.id == 'us-user-gaming-boardgamegeek':
        # Same username namespace; retain the catalogue's old display route.
        urls.add('https://boardgamegeek.com/user/{username}')
    return site.url.rstrip("/") in urls


def mssg_catalogue(site):
    return (
        site.id == "mssg-me"
        and site.url == "https://mssg.me/{username}"
        and not site.url_probe
        and site.method == "GET"
        and not site.payload
        and not site.strip_chars
        and site.id_type == "username"
        and not site.headers
    )


def mssg_outcome(code, text, query, headers):
    from urllib.parse import quote

    from .models import Status

    url = "https://mssg.me/" + quote(query, safe="")
    issue, reason = http_issue(code, headers, text, accepted=(200, 404))
    if issue is not None:
        return issue, {}, reason
    try:
        response = prepare("mssg_me", query, url, httpx.Response(code, text=text, headers=headers))
        if code == 404:
            if clean_page(response.text).select("#page_404"):
                return Status.NOT_FOUND, {}, None
            raise ValueError("No explicit missing-profile template")
        return Status.FOUND, {"scope": "Public profile page; ownership is unverified"}, None
    except (ValueError, TypeError, AttributeError) as exc:
        return Status.UNKNOWN, {}, str(exc)


def _object(text):
    return json.loads(text, object_pairs_hook=_unique_object)


def _same(value, query):
    return isinstance(value, str) and value.casefold() == query.casefold()


def clean_page(text):
    page = BeautifulSoup(text, "html.parser")
    for comment in page.find_all(string=lambda v: isinstance(v, Comment)):
        comment.extract()
    for node in page.select("template, style, noscript"):
        node.decompose()
    for node in page.select("script[type]"):
        if node.get("type", "").lower() not in {
            "application/json",
            "application/ld+json",
            "text/javascript",
            "application/javascript",
            "module",
        }:
            node.decompose()
    return page


def active_markup(text):
    """Remove inert containers without reordering attributes used by legacy extractors."""

    class ActiveHTML(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=False)
            self.parts, self.ignored, self.depth = [], None, 0

        def handle_starttag(self, tag, attrs):
            if self.ignored:
                if tag == self.ignored:
                    self.depth += 1
                return
            kind = dict(attrs).get("type", "").lower()
            if (
                tag in {"template", "style", "noscript"}
                or tag == "script"
                and kind
                not in {
                    "",
                    "application/json",
                    "application/ld+json",
                    "text/javascript",
                    "application/javascript",
                    "module",
                }
            ):
                self.ignored, self.depth = tag, 1
            else:
                self.parts.append(self.get_starttag_text())

        def handle_endtag(self, tag):
            if self.ignored:
                if tag == self.ignored:
                    self.depth -= 1
                    if not self.depth:
                        self.ignored = None
            else:
                self.parts.append("</" + tag + ">")

        def handle_startendtag(self, tag, attrs):
            if not self.ignored and tag not in {"template", "style", "noscript"}:
                self.parts.append(self.get_starttag_text())

        def handle_data(self, data):
            if not self.ignored:
                self.parts.append(data)

        def handle_entityref(self, name):
            self.handle_data("&" + name + ";")

        def handle_charref(self, name):
            self.handle_data("&#" + name + ";")

        def handle_decl(self, decl):
            self.handle_data("<!" + decl + ">")

    parser = ActiveHTML()
    parser.feed(text)
    parser.close()
    return "".join(parser.parts)


def _one(values):
    if len(values) != 1:
        raise ValueError("No unambiguous profile record")
    return values[0]


def _script_object(page, marker):
    values = []
    decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
    for script in page.find_all("script"):
        text = script.string or ""
        for match in re.finditer(marker, text):
            value, _ = decoder.raw_decode(text[match.end() :].lstrip())
            values.append(value)
    return _one(values)


def prepare(provider, query, url, response):
    """Return a checked response or raise; unrecognized evidence is inconclusive."""
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 404, 410))
    if issue is not None:
        raise ValueError(reason)
    code = response.status_code
    try:
        actual_url = str(response.url)
    except (AttributeError, RuntimeError):
        actual_url = ""
    if actual_url:
        actual, expected = urlsplit(actual_url), urlsplit(url)
        paths = {expected.path.rstrip("/")}
        if provider == "rumble":
            paths.add(expected.path.rstrip("/") + "/about")
        if (
            actual.scheme != expected.scheme
            or actual.netloc.casefold() != expected.netloc.casefold()
            or unquote(actual.path).rstrip("/") not in {unquote(p) for p in paths}
        ):
            raise ValueError("Response URL does not match the requested profile endpoint")
    if provider in {"boot_dev", "cameo", "wisio", "medal"}:
        data = _object(response.text)
        if provider == "wisio" and urlsplit(url).path.endswith("/is_username_allowed"):
            if code != 200 or type(data) is not bool:
                raise ValueError("No typed username availability response")
            return response
        if code != 200:
            allowed = (
                provider == "boot_dev"
                and code == 404
                and data == {"error": "User not found"}
                or provider == "cameo"
                and code == 404
                and isinstance(data, dict)
                and set(data) == {"message"}
                and isinstance(data["message"], str)
                and _same(data["message"], "We could not find the user: " + query)
            )
            if not allowed:
                raise ValueError("No explicit missing-profile evidence")
            return response
        if not isinstance(data, dict) or has_service_error(data):
            raise ValueError("Conflicting profile API response")
        if provider == "boot_dev":
            profile = data.get("data")
            if (
                data.get("status") != "success"
                or not isinstance(profile, dict)
                or has_service_error(profile)
                or not _same(profile.get("handle"), query)
            ):
                raise ValueError("Boot.dev returned a different or invalid handle")
        elif provider == "medal":
            if data.get("valid") is not True or type(data.get("exists")) is not bool:
                raise ValueError("No typed Medal username verdict")
            if "username" in data and not _same(data["username"], query):
                raise ValueError("Medal returned a different username")
        elif not _same(data.get("username"), query):
            raise ValueError("Returned profile does not match the requested username")
        return response

    page = clean_page(response.text)
    body = active_markup(response.text)
    if code != 200:
        # Only the selected extractor's explicit missing template can decide;
        # no embedded positive record may coexist with it.
        if page.select('script[type="application/ld+json"], #app[data-page]'):
            raise ValueError("Conflicting profile and missing-page evidence")
        return httpx.Response(code, text=body, headers=response.headers, request=httpx.Request("GET", url))
    if provider == "gumroad":
        from .profile_page_contracts import _url_key

        declared = [n.get("href", "") for n in page.select('link[rel~="canonical"]')]
        declared += [n.get("content", "") for n in page.select('meta[property="og:url"]')]
        if any(_url_key(value) != _url_key(url) for value in declared):
            raise ValueError("Conflicting Gumroad profile URL")
        headings = " ".join(n.get_text(" ", strip=True) for n in page.select("title,h1,h2")).casefold()
        if "page not found" in headings or "user not found" in headings:
            raise ValueError("Conflicting Gumroad profile and missing-page evidence")
        app = _one(page.select("#app[data-page]"))
        root = _object(app["data-page"])
        props = root.get("props") if isinstance(root, dict) else None
        profile = props.get("creator_profile") if isinstance(props, dict) else None
        if (
            not isinstance(profile, dict)
            or has_service_error(root)
            or has_service_error(props)
            or has_service_error(profile)
            or profile.get("subdomain") != query.lower() + ".gumroad.com"
        ):
            raise ValueError("No matching Gumroad creator")
    elif provider == "payhip":
        root = _script_object(page, r"window\.payhipShop\s*=\s*")
        profile = root.get("user") if isinstance(root, dict) else None
        if (
            not isinstance(profile, dict)
            or has_service_error(root)
            or has_service_error(profile)
            or not _same(profile.get("username"), query)
        ):
            raise ValueError("No matching Payhip shop")
    elif provider == "stackb":
        profiles = []
        for node in page.select('script[type="application/ld+json"]'):
            root = _object(node.string or "")
            if isinstance(root, dict) and root.get("@type") == "ProfilePage":
                profiles.append(root)
        root = _one(profiles)
        profile = root.get("mainEntity")
        if (
            not isinstance(profile, dict)
            or profile.get("@type") != "Person"
            or has_service_error(root)
            or has_service_error(profile)
            or not isinstance(profile.get("identifier"), str)
            or not _same(profile["identifier"].removeprefix("@"), query)
        ):
            raise ValueError("No matching StackB person")
        if any(
            record.get("url") and record["url"].rstrip("/").casefold() != url.rstrip("/").casefold()
            for record in (root, profile)
        ):
            raise ValueError("Conflicting StackB profile URL")
    elif provider == "kickstarter":
        expected = url.removesuffix("/about").rstrip("/").casefold()
        urls = [n.get("content", "").rstrip("/").casefold() for n in page.select('meta[property="og:url"]')]
        types = [n.get("content") for n in page.select('meta[property="og:type"]')]
        if (
            not urls
            or any(u != expected for u in urls)
            or not types
            or any(t not in {"profile", "kickstarter:creator"} for t in types)
        ):
            raise ValueError("No matching Kickstarter profile metadata")
    elif provider == "indiegogo":
        root = _script_object(page, r"'App\.Views\.UserProfileView',\s*App\.Views\.UserProfileView,\s*")
        profile = root.get("props") if isinstance(root, dict) else None
        if not isinstance(profile, dict) or has_service_error(profile) or not _same(profile.get("userUrlName"), query):
            raise ValueError("No matching Indiegogo user")
    elif provider == "weblancer":
        from ..vendor.user_scanner.core.nextjs import iter_next_app_flight_chunks

        found = []
        decoder = json.JSONDecoder(object_pairs_hook=_unique_object)
        for chunk in iter_next_app_flight_chunks(body):
            for match in re.finditer(r'"user":', chunk):
                record, _ = decoder.raw_decode(chunk[match.end() :].lstrip())
                if isinstance(record, dict) and _same(record.get("login"), query):
                    found.append(record)
        profile = _one(found)
        if has_service_error(profile) or type(profile.get("id")) is not int or profile["id"] <= 0:
            raise ValueError("No coherent Weblancer user identity")
    elif provider == "fredmiranda":
        headings = [n.get_text(" ", strip=True) for n in page.select('font[size="3"][color="FFFFCC"] > b')]
        if not headings or any(not _same(h, query) for h in headings):
            raise ValueError("No matching FredMiranda profile heading")
    elif provider == "rumble":
        urls = [n.get("href", "") for n in page.select('link[rel~="canonical"]')]
        if not urls or any(u.rstrip("/").casefold() != url.rstrip("/").casefold() for u in urls):
            raise ValueError("Rumble canonical URL does not match requested user")
        profile = _script_object(page, r'(?=\{"type":"user","url":)')
        if (
            not isinstance(profile, dict)
            or has_service_error(profile)
            or profile.get("type") != "user"
            or not _same(profile.get("url", "").rstrip("/"), url.rstrip("/"))
        ):
            raise ValueError("No matching Rumble user object")
    elif provider == "mssg_me":
        urls = [n.get("content", "") for n in page.select('meta[property="og:url"]')]
        urls += [n.get("href", "") for n in page.select('link[rel~="canonical"]')]
        if not urls or any(unquote(u).rstrip("/").casefold() != unquote(url).rstrip("/").casefold() for u in urls):
            raise ValueError("No matching mssg.me profile URL")
        if not page.select('link[rel~="manifest"][href="/favicons/site.webmanifest"]'):
            raise ValueError("No public mssg.me profile manifest")
    return httpx.Response(code, text=body, headers=response.headers, request=httpx.Request("GET", url))


def validate(url, process, *, _provider, _query, _impersonate=False, **kwargs):
    from ..vendor.user_scanner.core.orchestrator import generic_validate

    if (
        not isinstance(_query, str)
        or not _query
        or any(ord(c) < 32 for c in _query)
        or any(c in _query for c in "/\\?#")
    ):
        return Result.skipped(url=kwargs.get("show_url") or url)
    if _impersonate:
        from ..vendor.user_scanner.core.impersonate import impersonate_validate

        transport = impersonate_validate
        kwargs.pop("follow_redirects", None)
        kwargs["allow_redirects"] = False
    else:
        transport = generic_validate
        kwargs.pop("allow_redirects", None)
        kwargs["follow_redirects"] = False

    def checked(response):
        try:
            result = process(prepare(_provider, _query, url, response))
            if result.status.name == "TAKEN":
                if result.extra is None:
                    result.extra = {}
                result.extra.setdefault("scope", "Public profile evidence; identity and ownership are unverified")
            return result
        except (ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
            return Result.error(str(exc), url=kwargs.get("show_url") or url)

    return transport(url, checked, **kwargs)
