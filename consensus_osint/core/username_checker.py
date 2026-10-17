"""Data-driven username check: build the request for a :class:`Site`, run it,
and evaluate the response with the unified detection rules.

Detection semantics (superset of Sherlock, Maigret and WhatsMyName):

``status_code``   FOUND when 2xx and status not in ``missing_status``.
``message``       NOT_FOUND when any ``missing_strings`` occurs in the body; when
                  ``found_strings`` is non-empty at least one must occur, else NOT_FOUND;
                  otherwise FOUND.
``response_url``  request made without following redirects; FOUND when 2xx and
                  (if given) a presence string occurs.
``wmn``           FOUND when status in ``found_status`` and ``found_strings`` occur
                  and no ``missing_strings`` occur; NOT_FOUND when status in
                  ``missing_status`` and (if given) ``missing_strings`` occur or the
                  presence string is absent; anything else UNKNOWN.
A list of types means all rules are evaluated and any NOT_FOUND wins.

Before the rules run, bot-protection / error pages are classified (see
``errors.py``) and yield BLOCKED / RATE_LIMITED / UNKNOWN instead of a silent
false negative.  Sites flagged with TLS-fingerprint protection are requested
through curl_cffi impersonation; a blocked plain request is retried once with
impersonation as well.
"""
from __future__ import annotations

import asyncio
import logging
import time

from .errors import detect_error_page
from .http import Http, Response
from .models import Finding, Status
from .sitesdb import Site

log = logging.getLogger("consensus.username")


def _any_in(needles, hay: str) -> bool:
    return any(n and n in hay for n in needles)


# The site refused to process the request (bad form, missing token, wrong method):
# it never looked the name up, so the answer is unknown, not "no account".
REJECTED_STATUSES = frozenset({400, 405, 406, 409, 415, 422, 423})

_SOFT_404_PHRASES = ("not found", "not exist", "no such user", "no such page", "nothing here", "404",
                     "nicht gefunden", "introuvable", "no encontrad", "nÃ£o encontrad", "Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½")


def _heading(text: str, tag: str) -> str:
    """Text of the first <tag>...</tag> in the page, lower-cased ('' if absent)."""
    low = text[:20000].lower()
    i = low.find("<" + tag)
    if i < 0:
        return ""
    j = low.find(">", i)
    k = low.find("</" + tag, j)
    return low[j + 1:k].strip() if 0 < j < k else ""


def _soft_404(text: str, username: str = "") -> bool:
    """A 200 whose <title> or first <h1> announces a missing page is a soft 404.

    Only consulted for rules with no positive marker: a page carrying the profile
    marker is a profile whatever its title says.  The username itself is blanked
    out first, so "fred404" or "notfound_jim" cannot trip the phrase list.
    """
    head = _heading(text, "title") + " | " + _heading(text, "h1")
    if username:
        head = head.replace(username.lower(), " ")
    return head.strip(" |") != "" and any(p in head for p in _SOFT_404_PHRASES)


def evaluate(site: Site, resp: Response, username: str) -> tuple:
    """Return (Status, method_description, note)."""
    if not resp.ok:
        low = (resp.error or "").lower()
        if "timeout" in low:
            return Status.ERROR, "network", "timeout"
        return Status.ERROR, "network", resp.error

    text = resp.text or ""
    status = resp.status
    d = site.detect
    from .selected_profile_guards import mssg_catalogue, mssg_outcome
    if mssg_catalogue(site):
        result, _, note = mssg_outcome(status, text, username, resp.headers)
        return result, "bound public profile page", note
    if d.get("type") == "profile_api":
        from .community_profiles import outcome
        result, _, note = outcome(d.get("contract"), status, text, username, resp.headers, site.profile_url(username))
        return result, "identity-bound community API", note
    types = d.get("type") or "status_code"
    if isinstance(types, str):
        types = [types]
    missing_status = d.get("missing_status") or []

    err = detect_error_page(text, status, site.fail_flags, site.ignore_403 or (403 in missing_status))
    if err is not None:
        if err.kind == "Rate limited":
            return Status.RATE_LIMITED, "error-page", str(err)
        if err.kind in ("Captcha", "Bot protection", "Access denied", "Request blocked", "Login required", "Censorship"):
            return Status.BLOCKED, "error-page", str(err)
        return Status.UNKNOWN, "error-page", str(err)

    from .threads_contracts import catalogue_outcome as threads_outcome
    from .threads_contracts import catalogue_scope as threads_scope

    if threads_scope(site):
        outcome, note = threads_outcome(resp, username)
        return outcome, "query-bound Threads profile evidence", note

    from .forge_profiles import catalogue_scope, profile_outcome

    if catalogue_scope(site):
        outcome, _, note = profile_outcome(status, text, username, resp.headers)
        return outcome, "public-profile JSON binding", note

    from .profile_api_contracts import catalogue_scope as api_scope
    from .profile_api_contracts import outcome as api_outcome

    scope = api_scope(site)
    if scope:
        outcome, _, note = api_outcome(scope, status, text, username, resp.headers)
        return outcome, "typed username API evidence", note

    from .profile_page_contracts import catalogue_scope as page_scope
    from .profile_page_contracts import verdict as page_verdict

    scope = page_scope(site)
    if scope:
        outcome, note = page_verdict(scope, status, text, username, resp.headers, resp.url,
                                     missing_strings=d.get("missing_strings") or ())
        return outcome, "public profile page evidence", note

    def _sub(strings):
        if not strings:
            return strings
        if not any("{username}" in s for s in strings):
            return strings
        return [s.replace("{username}", username) for s in strings]

    found_strings = _sub(d.get("found_strings") or [])
    missing_strings = _sub(d.get("missing_strings") or [])
    found_status = d.get("found_status") or []

    if status in REJECTED_STATUSES and status not in missing_status and status not in found_status:
        return Status.UNKNOWN, "status", f"request rejected (HTTP {status})"

    verdicts = []
    for t in types:
        if t == "wmn":
            ok_status = status in found_status if found_status else 200 <= status < 300
            has_found = _any_in(found_strings, text) if found_strings else True
            has_missing = _any_in(missing_strings, text) if missing_strings else False
            if ok_status and has_found and not has_missing:
                verdicts.append(Status.FOUND)
            elif has_missing:
                verdicts.append(Status.NOT_FOUND)
            elif missing_status and status in missing_status:
                verdicts.append(Status.NOT_FOUND)
            elif ok_status and found_strings and not has_found:
                # the site answered normally but the page is not a profile
                verdicts.append(Status.NOT_FOUND)
            else:
                verdicts.append(Status.UNKNOWN)
        elif t == "message":
            if _any_in(missing_strings, text):
                verdicts.append(Status.NOT_FOUND)
            elif 300 <= status < 400 and not (found_strings and _any_in(found_strings, text)):
                # an unfollowed redirect carrying none of the markers proves nothing either
                # way - it used to count as "found" for rules that only list a not-found text
                verdicts.append(Status.UNKNOWN)
            elif found_strings and not _any_in(found_strings, text):
                verdicts.append(Status.NOT_FOUND)
            else:
                # Maigret heuristic: a non-ASCII username that never appears in
                # the page is most likely a generic error page.
                if not found_strings and any(ord(c) > 127 for c in username) and username not in text:
                    verdicts.append(Status.NOT_FOUND)
                else:
                    verdicts.append(Status.FOUND)
        elif t == "response_url":
            if 200 <= status < 300 and (not found_strings or _any_in(found_strings, text)):
                verdicts.append(Status.FOUND)
            else:
                verdicts.append(Status.NOT_FOUND)
        else:  # status_code
            if 200 <= status < 300 and status not in missing_status:
                if missing_strings and _any_in(missing_strings, text):
                    verdicts.append(Status.NOT_FOUND)
                elif found_strings and not _any_in(found_strings, text):
                    # markers listed next to a status rule are evidence too: the
                    # site answered normally but the page is not a profile
                    verdicts.append(Status.NOT_FOUND)
                else:
                    verdicts.append(Status.FOUND)
            else:
                verdicts.append(Status.NOT_FOUND)

    method = "+".join(types)
    if Status.NOT_FOUND in verdicts:
        return Status.NOT_FOUND, method, None
    if Status.UNKNOWN in verdicts:
        return Status.UNKNOWN, method, "ambiguous response"
    # A rule with no positive marker only knows that "the page loaded"; an empty
    # body is not a page at all (a CDN stub, a block answered with 200), so it
    # proves nothing - unless the probe is a HEAD, where no body is expected.
    positive = bool(found_strings) and _any_in(found_strings, text)
    if not positive:
        if not text.strip() and (site.method or "GET").upper() != "HEAD":
            return Status.UNKNOWN, method, "empty response"
        if _soft_404(text, username):
            # the page loaded, but its own title says there is nothing here
            return Status.NOT_FOUND, method, "soft 404"
        if not missing_strings and (site.method or "GET").upper() != "HEAD" and username.lower() not in text.lower():
            # a status-only rule has nothing but "the page loaded"; a page that never even
            # names the account it supposedly belongs to is not evidence of that account
            return Status.UNKNOWN, method, "page does not mention the name"
    return Status.FOUND, method, None


def _site_deadline(http, retry_impersonate):
    """Budget all transport/fallback stages, not just each individual request.

    Keep the existing request timeout meaning. Solvers have separate bounded
    budgets; this outer deadline also covers their queue/startup waits. Async
    cancellation cannot pre-empt synchronous parsing or blocked native code.
    """
    from .http import _positive_timeout

    def duration(resource, name, default):
        value = getattr(resource, name, default)
        return value if _positive_timeout(value) else default

    budget = duration(http, "timeout", 15.0) * (2 if retry_impersonate else 1)
    solver = getattr(http, "flaresolverr", None)
    if solver is not None:
        budget += duration(solver, "timeout", 75.0) + 15.0
    browser = getattr(http, "browser", None)
    if browser is not None:
        budget += duration(browser, "timeout", 35.0) + duration(browser, "challenge_wait", 30.0)
    return budget + 10.0


async def check_site(
    site: Site,
    username: str,
    http: Http,
    *,
    extract: bool = True,
    query_type: str = "username",
    retry_impersonate: bool = True,
) -> Finding:
    """Check one catalogue entry with an overall asynchronous deadline."""
    started = time.perf_counter()
    deadline = _site_deadline(http, retry_impersonate)
    task = asyncio.create_task(_check_site(site, username, http, extract=extract,
                                          query_type=query_type, retry_impersonate=retry_impersonate))
    try:
        return await asyncio.wait_for(task, timeout=deadline)
    except asyncio.TimeoutError:
        if not task.cancelled():
            raise
        return Finding(query=username, query_type=query_type, site=site.name,
                       site_id=site.id, category=site.category, tags=list(site.tags),
                       source="sites-db", nsfw=site.nsfw, url=site.profile_url(username),
                       status=Status.ERROR, elapsed=round(time.perf_counter() - started, 3),
                       error=f"site deadline exceeded after {deadline:g}s")


async def _check_site(
    site: Site,
    username: str,
    http: Http,
    *,
    extract: bool = True,
    query_type: str = "username",
    retry_impersonate: bool = True,
) -> Finding:
    """Check one username on one data-driven site."""
    lookup_username = site.normalise_username(username)
    base = dict(
        query=username,
        query_type=query_type,
        site=site.name,
        site_id=site.id,
        category=site.category,
        tags=list(site.tags),
        source="sites-db",
        nsfw=site.nsfw,
        url=site.profile_url(username),
        # Provenance travels with the result: which upstream projects listed this
        # site, and whose detection rule was actually used.  Underscore-prefixed so
        # it stays out of the terminal's scraped-metadata line and out of the
        # confidence "richness" bonus, while still reaching the saved reports.
        extra={
            "_sources": list(site.sources),
            "_source_count": len(site.sources),
            "_detect_source": site.detect_source,
            "_weak_rule": bool(site.weak),
        },
    )
    if lookup_username != username:
        base["extra"]["_lookup_query"] = lookup_username
    if site.audit_disabled_reason or site.disabled:
        return Finding(status=Status.SKIPPED, error=site.audit_disabled_reason or site.disabled_reason or "disabled", **base)
    if not lookup_username:
        return Finding(status=Status.SKIPPED, error="identifier is empty after applying this site's formatting rule", **base)
    if not site.username_allowed(lookup_username):
        return Finding(status=Status.SKIPPED, error="username format not accepted by site", **base)
    community_contract = site.detect.get("contract") if site.detect.get("type") == "profile_api" else None
    if community_contract:
        from .community_profiles import valid_query
        if site.method != "GET" or site.payload is not None or not valid_query(community_contract, lookup_username):
            return Finding(status=Status.SKIPPED, error="A public GET lookup for one valid community username is required", **base)
    if site.protocol == "tor" and not http.proxy:
        return Finding(status=Status.SKIPPED, error="onion site requires --tor", **base)

    url = site.probe_url(username)
    data, js = site.build_body(username)
    headers = site.build_headers(username)

    from .profile_api_contracts import catalogue_scope as guarded_api_scope
    scope = guarded_api_scope(site)
    if scope == "twitch":
        base["site"] = "TwitchTracker"
        base["extra"]["twitch_profile_url"] = base["url"]
        base["url"] = url
        base["extra"]["scope"] = "Public TwitchTracker listing; not verification of a current Twitch account"
    if scope == "substack":
        base["extra"]["scope"] = "Substack publication; not a same-named user account"
    from .profile_page_contracts import catalogue_scope as guarded_page_scope
    request_redirects = False if scope in ("twitter-x", "twittercommunity-com", "twitter-archived-profile", "twitter-archived-tweets", "youporn-pornstars", "youporn-channels", "xvideos-pornstars", "xvideos-users-channels", "xvideosmodels", "xvideos-red", "xnxx-porn-maker", "xnxx-pornstars", "xnxx-xnxx-com", "xvideos", "stripchat", "spankbang", "erome", "e621", "adultism", "bdsmlr", "tiktok", "tiktok-tiktok-com", "youtube", "x", "tumblr-tumblr-com", "bitchute", "tenor", "livejournal", "pr0gramm", "fotka-fotka-com", "sports-tracker", "gravatar-gravatar-com", "giphy", "giphy-channel", "discord", "discord-invite", "clubhouse", "aparat", "vinted", "themeforest", "pastebin", "omg-lol", "freelancer", "stats-fm", "mixcloud", "bandlab-bandlab-com", "vimeo", "twitch", "taplink", "substack", "substack-substack-com", "solo-to", "medium", "medium-medium-com", "lnk-bio", "boosty", "linktree", "bio-site", "fansly", "fansly-fansly-com", "picsart", "flickr-albums", "35photo", "unsplash", "myminifactory", "quora", "quora-com", "academia", "d3ru", "warframe-market", "monkeytype", "kick", "etoro", "fragment", "cropty", "destream", "donatello", "ko-fi", "microsoft-learn", "sourceforge", "sourceforge-sourceforge-net", "npm", "wordpress-org-forums", "hackerone", "devpost-com", "hackerone-com", "hackerrank-hackerrank-com", "bugcrowd-bugcrowd-com", "codeforces", "leetcode-leetcode-com", "codewars", "lichess-org", "chess-com", "scratch", "wikipedia-en-wikipedia-org", "github-gists") else site.follow_redirects
    if scope in ("fansly", "fansly-fansly-com"):
        from .fansly_contracts import valid_user
        if not valid_user(lookup_username):
            return Finding(status=Status.SKIPPED, error="One Fansly username is required", **base)
    if scope == "gravatar-gravatar-com":
        url += ".json"
    if scope in ("twitter-archived-profile", "twitter-archived-tweets"):
        from .twitter_archive_contracts import request_url
        url = request_url(lookup_username, scope == "twitter-archived-tweets")
    if scope == "twittercommunity-com":
        from urllib.parse import quote
        url = "https://twittercommunity.com/u/" + quote(lookup_username, safe="") + ".json"
    if scope == "xvideos":
        from urllib.parse import quote
        url = "https://www.xvideos.com/profiles/" + quote(lookup_username, safe="")
    if scope == "spankbang":
        from urllib.parse import quote
        url = "https://spankbang.com/profile/" + quote(lookup_username, safe="")
        base["url"] = url
    if scope == "e621":
        from urllib.parse import quote

        from .e621_contracts import HEADERS
        url = "https://e621.net/users/" + quote(lookup_username, safe="") + ".json"
        headers = {key: value for key, value in headers.items() if key.lower() not in ("user-agent", "accept")}
        headers.update(HEADERS)
    if scope == "bdsmlr":
        url = "https://api-prod.bdsmlr.com/v2/api/get-blog"
    if scope in ("tiktok", "tiktok-tiktok-com"):
        from urllib.parse import quote, urlencode
        url = "https://www.tiktok.com/oembed?" + urlencode({"url": "https://www.tiktok.com/@" + quote(lookup_username, safe="")})
    if scope == "x":
        from .x_contracts import valid_user
        if not valid_user(lookup_username):
            return Finding(**base, status=Status.SKIPPED, error="Invalid X username")
    if scope == "tumblr-tumblr-com":
        from .tumblr_contracts import valid_user
        if not valid_user(lookup_username):
            return Finding(**base, status=Status.SKIPPED, error="Invalid Tumblr blog name")
        lookup_username = lookup_username.lower()
        url = "https://www.tumblr.com/" + lookup_username
        base["url"] = url
    if scope == "livejournal":
        from urllib.parse import quote
        url = "https://www.livejournal.com/profile/?user=" + quote(lookup_username, safe="")
        base["url"] = url
    if scope == "unsplash":
        from urllib.parse import quote
        url = "https://unsplash.com/napi/users/" + quote(lookup_username, safe="")
    if scope == "quora-com":
        from urllib.parse import quote
        url = "https://www.quora.com/profile/" + quote(lookup_username, safe="")
        base["url"] = url
    if scope == "d3ru":
        from urllib.parse import quote
        url = "https://d3.ru/user/" + quote(lookup_username, safe="") + "/"
    if scope == "monkeytype":
        url += "?isUid=false"
    if scope == "sourceforge":
        from urllib.parse import quote
        url = "https://sourceforge.net/rest/u/" + quote(lookup_username, safe="") + "/profile"
    if scope == "npm":
        headers = {**headers, "x-spiferack": "1"}
    if scope == "hackerone":
        from urllib.parse import quote
        data = None
        js = {"query": "query($url: URI!) { resource(url: $url) { ... on User { username } } }",
              "variables": {"url": "https://hackerone.com/" + quote(lookup_username, safe="")}}
    if guarded_page_scope(site) == "atcoder":
        request_redirects = False
    if community_contract:
        request_redirects = False
    from .selected_profile_guards import mssg_catalogue
    if mssg_catalogue(site):
        request_redirects = False
    if scope == "wikipedia-en-wikipedia-org" and ("|" in lookup_username or any(ord(c) < 32 for c in lookup_username)):
        return Finding(status=Status.SKIPPED, error="A single MediaWiki username is required", **base)
    if scope == "codeforces" and (";" in lookup_username or any(ord(c) < 32 for c in lookup_username)):
        return Finding(status=Status.SKIPPED, error="A single Codeforces handle is required", **base)
    if scope == "chess-com":
        url = site.probe_url(username.lower())
    t0 = time.perf_counter()
    resp = await http.request(
        site.method,
        url,
        headers=headers,
        data=data,
        json=js,
        follow_redirects=request_redirects,
        impersonate=site.needs_impersonation,
        encoding=site.encoding,
    )
    status, method, note = evaluate(site, resp, lookup_username)
    if status is Status.BLOCKED and retry_impersonate and not resp.impersonated:
        resp2 = await http.request(
            site.method, url, headers=headers, data=data, json=js,
            follow_redirects=request_redirects, impersonate=True, encoding=site.encoding,
        )
        if resp2.ok and resp2.impersonated:
            s2, m2, n2 = evaluate(site, resp2, lookup_username)
            if s2 is not Status.BLOCKED:
                resp, status, method, note = resp2, s2, m2 + " (impersonated)", n2
    if status is Status.BLOCKED and http.has_challenge_solver and js is None and data is None:
        resp3 = await http.solve_challenge(site.method, url)
        if resp3 is not None and resp3.ok:
            s3, m3, n3 = evaluate(site, resp3, lookup_username)
            if s3 is not Status.BLOCKED:
                resp, status, method, note = resp3, s3, m3 + " (browser)", n3

    f = Finding(status=status, method=method, http_status=resp.status if resp.ok else None,
                elapsed=round(time.perf_counter() - t0, 3), error=note, **base)
    if status is Status.FOUND and extract and resp.text:
        from .forge_profiles import catalogue_scope, profile_outcome
        from .profile_api_contracts import catalogue_scope as api_scope
        from .profile_api_contracts import outcome as api_outcome

        if community_contract:
            from .community_profiles import outcome
            f.extra.update(outcome(community_contract, resp.status, resp.text, lookup_username, resp.headers, f.url)[1])
        elif catalogue_scope(site):
            f.extra.update(profile_outcome(resp.status, resp.text, lookup_username, resp.headers)[1])
        elif api_scope(site):
            f.extra.update(api_outcome(api_scope(site), resp.status, resp.text, lookup_username, resp.headers)[1])
        else:
            f.extra.update(extract_metadata(resp.text, f.url or url))
    if status is Status.FOUND:
        from .confidence import base_confidence

        # Evidence quality travels with the hit: a profile page normally names the
        # account it belongs to, so a page that never mentions the query is scored
        # lower (underscore-prefixed: metadata, not scraped profile data).
        from .html_evidence import mentions_query

        # A community contract only reports FOUND after binding the returned account
        # to the query under that service's own name rules (a wiki answers
        # "some_name" as "Some name"), which a text search cannot reproduce.
        f.extra["_page_mentions_query"] = bool(community_contract) or mentions_query(resp.text, lookup_username)
        f.confidence = base_confidence(f, site)
    return f


def extract_metadata(html: str, url: str) -> dict:
    """Pull structured profile data out of a page with socid-extractor (Maigret's
    extraction engine).  Silently returns {} when the library is missing."""
    try:
        from socid_extractor import extract  # type: ignore
    except Exception:  # noqa: BLE001
        return {}
    try:
        data = extract(html) or {}
        if not data:
            return {}
        out = {}
        for k, v in data.items():
            if v in (None, "", [], {}):
                continue
            key = str(k).strip().lower().replace(" ", "_")
            out[key] = v if isinstance(v, (str, int, float, bool)) else str(v)
        return out
    except Exception:  # noqa: BLE001
        return {}
