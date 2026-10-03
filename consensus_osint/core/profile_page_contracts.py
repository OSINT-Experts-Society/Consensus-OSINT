"""Evidence guards for retained public profile pages, not identity ownership."""
from __future__ import annotations

import re
from urllib.parse import quote, urlencode, urljoin, urlsplit

from bs4 import BeautifulSoup

from .mailbox_contracts import http_issue
from .models import Status

ROUTES = {
    "atcoder": ["https://atcoder.jp/users/{query}"],
    "bio_link": ["https://bio.link/{query}"],
    "gumroad": ["https://{query}.gumroad.com/", "https://www.gumroad.com/{query}"],
    "itch_io": ["https://itch.io/profile/{query}"],
    "bitbucket": ["https://bitbucket.org/{query}/"],
    "crowdin": ["https://crowdin.com/profile/{query}"],
    "luarocks": ["https://luarocks.org/modules/{query}"],
    "liberapay": ["https://en.liberapay.com/{query}", "https://liberapay.com/{query}"],
    "allthelyrics": ["https://www.allthelyrics.com/forum/member.php?username={query}",
                    "https://www.allthelyrics.com/forum/members/{query}.html"],
    "newamerica": ["https://www.newamerica.org/our-people/{query}/", "https://www.newamerica.org/people/{query}/"],
    "speakerdeck": ["https://speakerdeck.com/{query}"],
    "letterboxd": ["https://letterboxd.com/{query}/"],
    "tripadvisor": ["https://www.tripadvisor.com/Profile/{query}", "https://tripadvisor.com/Profile/{query}",
                    "https://tripadvisor.com/members/{query}", "https://www.tripadvisor.com/members/{query}"],
}
CATALOGUE = {
    "atcoder": "atcoder",
    "biolink": "bio_link", "gumroad": "gumroad", "gumroad-x-gumroad-com": "gumroad",
    "itch-io-2": "itch_io", "bitbucket": "bitbucket", "crowdin": "crowdin",
    "liberapay": "liberapay", "allthelyrics": "allthelyrics", "speaker-deck": "speakerdeck",
    "letterboxd": "letterboxd",
    "tripadvisor": "tripadvisor", "tripadvisor-tripadvisor-com": "tripadvisor",
}

PROFILE_MODULES = {
    "us-user-creator-bio_link": "bio_link",
    "us-user-creator-itch_io": "itch_io",
    "us-user-social-speakerdeck": "speakerdeck",
    "us-user-social-letterboxd": "letterboxd",
    "us-user-creator-gumroad": "gumroad",
    "us-user-donation-liberapay": "liberapay",
}


def same_profile_lookup(module, site):
    """Exact reviewed request templates, independent of the current input/options."""
    provider = PROFILE_MODULES.get(module.id)
    if not provider or module.kind != "username" or module.source != "user-scanner" or not module.url_main:
        return False
    expected = ROUTES[provider][0].replace("{query}", "{username}")
    return module.url_main.rstrip("/") == expected.rstrip("/") and catalogue_scope(site) == provider


def profile_alias_sites(module, sites):
    """Two reviewed cross-host profiles; never create general domain aliases."""
    if module.id not in {"us-user-creator-gumroad", "us-user-donation-liberapay"}:
        return []
    return [site for site in sites if same_profile_lookup(module, site)]


def prefer_profile_module(module, site, query=None):
    """Keep reviewed profile fields only when replacing the same lookup route."""
    provider = PROFILE_MODULES.get(module.id)
    if not same_profile_lookup(module, site):
        return False
    if provider == "itch_io" and query is not None and not re.fullmatch(r"[a-z0-9_-]{2,25}", query):
        return False  # The catalogue may support input the native validator rejects.
    if provider == "gumroad" and (query is None or not re.fullmatch(r"[a-z0-9]{3,20}", query)):
        return False  # Do not replace a catalogue's wider/transformed input scope.
    return True


def catalogue_scope(site):
    provider = CATALOGUE.get(site.id)
    expected_strip = "." if site.id == "gumroad-x-gumroad-com" else ""
    if (not provider or site.method != "GET" or site.id_type != "username" or site.payload or site.strip_chars != expected_strip
            or site.url_probe or any(key.lower() not in {"accept", "accept-language", "user-agent"} for key in site.headers)):
        return None
    return provider if site.url.rstrip("/") in [r.replace("{query}", "{username}").rstrip("/") for r in ROUTES[provider]] else None


def _url_key(value):
    try:
        p = urlsplit(value)
        if p.scheme != "https" or p.username is not None or p.password is not None or p.port not in (None, 443):
            return None
        if any(ord(c) < 33 or ord(c) == 127 for c in value):
            return None
        return p.hostname, p.path.rstrip("/").casefold(), p.query
    except (TypeError, ValueError):
        return None


def verdict(provider, code, text, query, headers, final_url="", missing_strings=()):
    issue, note = http_issue(code, headers, text, accepted=(200, 404, 410))
    if issue is not None:
        return issue, note
    unknown = (Status.UNKNOWN, "The page lacks an unambiguous profile for the requested identifier")
    page = BeautifulSoup(text or "", "html.parser")
    for node in page(["script", "style", "template"]):
        node.decompose()
    title = page.title.get_text(" ", strip=True) if page.title else ""
    visible = page.get_text(" ", strip=True)
    encoded = quote(query, safe="")
    expected = [r.format(query=encoded) for r in ROUTES[provider]]
    if provider == "allthelyrics":
        expected[0] = "https://www.allthelyrics.com/forum/member.php?" + urlencode({"username": query})
    keys = {_url_key(url) for url in expected}
    declared = [node.get("href") for node in page.select('link[rel~="canonical"][href]')]
    declared += [node.get("content") for node in page.select('meta[property="og:url"][content]')]
    declared_keys = [_url_key(urljoin(expected[0], url)) for url in declared]
    if any(key not in keys for key in declared_keys):
        return unknown
    if final_url and _url_key(final_url) not in keys:
        return unknown
    canonical = bool(declared_keys)
    profile_usernames = [node.get("content", "") for node in page.select('meta[property="profile:username"]')]
    if profile_usernames and any(value.casefold() != query.casefold() for value in profile_usernames):
        return unknown
    bound = bool(profile_usernames)
    q = re.escape(query)
    heading = " ".join(node.get_text(" ", strip=True) for node in page.select("h1, h2"))
    named = bool(re.search(r"(?<![\w.-])" + q + r"(?![\w.-])", title + " " + heading, re.I))
    marker = False
    provider_missing = False
    if provider == "atcoder":
        # Contest Status is shared page furniture, not a username identity.
        section = page.find("h3", string=re.compile(r"^\s*Contest Status\s*$"))
        marker = bool(section and (bound or (canonical and named)))
        if code == 200 and marker and not re.search(r"not found|error|unavailable", title, re.I):
            return Status.FOUND, None
        return unknown  # An absent profile page is not account absence.
    if provider == "bio_link":
        marker = bound
    elif provider == "gumroad":
        marker = bool("gumroad" in title.casefold() and page.find("img", alt=re.compile(r"['’]s profile picture", re.I)))
    elif provider == "itch_io":
        marker = bool(page.select_one(".user_data") and (named or canonical or bound))
    elif provider == "bitbucket":
        marker = bound or bool(canonical and named and heading and "bitbucket" in title.casefold())
    elif provider == "crowdin":
        marker = bool(page.select_one("#profile-page") and (named or canonical or bound))
    elif provider == "luarocks":
        marker = bool(named and page.find("h3", string=re.compile(r"^\s*Registered\s*$", re.I)))
    elif provider == "liberapay":
        marker = bool(page.select_one(".profile-header") and (named or canonical or bound))
    elif provider == "allthelyrics":
        marker = bool(named and (page.select_one("#userinfo, #memberinfo, .memberinfo") or re.search(r"View Profile:\s*" + q, title, re.I)))
    elif provider == "newamerica":
        marker = bool(page.select_one("h1.header2-name") and heading)
    elif provider == "speakerdeck":
        marker = bool(page.h1 and re.search(r"\(" + q + r"\) on Speaker Deck", title, re.I))
    elif provider == "letterboxd":
        owners = (page.select("body[data-person]") or page.select(".profile-header[data-person]")
                  or page.select(".person-summary[data-person]"))
        if owners and any(node.get("data-person", "").casefold() != query.casefold() for node in owners):
            return unknown
        profile = page.select_one(".profile, .profile-header, .person-summary")
        marker = bool(owners or (profile and (bound or (canonical and "letterboxd" in title.casefold()))))
        missing_strings = (*missing_strings, "Letterboxd - Not Found",
                           "Sorry, we can’t find the page you’ve requested.")
    elif provider == "tripadvisor":
        marker = bool(page.h1 and "tripadvisor" in title.casefold() and "contributions" in visible.casefold()
                      and (bound or (canonical and named)))
        provider_missing = bool(page.select_one(".error404"))
        missing_strings = (*missing_strings, "This page is on vacation…")
    negative_text = (title + " " + heading if marker else visible).casefold()
    missing = any(phrase in negative_text for phrase in (
        "page not found", "user not found", "invalid user specified", "this user has not registered",
        "the page you’re looking for doesn’t exist", "response code: 404",
    )) or any(phrase.casefold() in negative_text for phrase in missing_strings if phrase)
    missing = missing or provider_missing or bool(page.select_one(".not_found_page")) or bool(code == 404 and page.select_one(".error-page"))
    if missing and marker:
        return Status.UNKNOWN, "The page contains conflicting profile and missing-profile evidence"
    if missing:
        return Status.NOT_FOUND, None
    if code == 200 and marker:
        return Status.FOUND, None
    return unknown


def native_guard(provider, response, query):
    from consensus_osint.vendor.user_scanner.core.result import Result

    try:
        final_url = str(response.url)
    except RuntimeError:  # HTTPX synthetic response without attached request
        final_url = ""
    status, note = verdict(provider, response.status_code, response.text, query, response.headers, final_url)
    if status is Status.FOUND:
        return None
    if status is Status.NOT_FOUND:
        return Result.available()
    return Result.error(note)
