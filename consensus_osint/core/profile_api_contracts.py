"""Typed evidence for explicitly scoped public user and availability APIs."""
from __future__ import annotations

import json
import re

from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def catalogue_scope(site):
    if site.id == "bdsmlr":
        from .email_validation import _unique_object
        try:
            payload = site.payload if isinstance(site.payload, dict) else json.loads(site.payload or "", object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return None
        if (site.url == "https://bdsmlr.com/blog/{username}" and site.url_probe == "https://api-prod.bdsmlr.com/v2/api/blog-tag-affinity"
                and site.method == "POST" and site.id_type == "username" and not site.strip_chars
                and site.payload_format == "simple" and site.headers == {"Content-Type": "application/json"}
                and payload == {"blog_name": "{username}"}):
            return site.id
        return None
    if site.id == "bitchute":
        from .email_validation import _unique_object
        try:
            payload = site.payload if isinstance(site.payload, dict) else json.loads(site.payload or "", object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return None
        if (site.url == "https://www.bitchute.com/channel/{username}/" and site.url_probe == "https://api.bitchute.com/api/beta/channel"
                and site.method == "POST" and site.id_type == "username" and not site.strip_chars
                and site.payload_format == "simple" and site.headers == {"Content-Type": "application/json"}
                and payload == {"channel_id": "{username}"}):
            return site.id
        return None
    if site.id == "discord":
        from .email_validation import _unique_object
        try:
            payload = site.payload if isinstance(site.payload, dict) else json.loads(site.payload or "", object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return None
        if (site.url == "https://discord.com" and site.url_probe == "https://discord.com/api/v9/unique-username/username-attempt-unauthed"
                and site.method == "POST" and site.id_type == "username" and not site.strip_chars
                and site.payload_format == "simple" and site.headers == {"Content-Type": "application/json"}
                and payload == {"username": "{username}"}):
            return site.id
        return None
    if site.id == "hackerone":
        from .email_validation import _unique_object
        try:
            payload = json.loads(site.payload or "", object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return None
        expected_query = "query($url: URI!) { resource(url: $url) { ... on User { username } } }"
        query = payload.get("query") if isinstance(payload, dict) else None
        if (site.url == "https://hackerone.com/{username}" and site.url_probe == "https://hackerone.com/graphql"
                and site.method == "POST" and site.id_type == "username" and not site.strip_chars
                and site.payload_format == "simple" and site.headers == {"Content-Type": "application/json"}
                and isinstance(query, str) and " ".join(query.replace("\\n", "\n").split()) == expected_query
                and payload == {"query": query, "variables": {"url": "{username}"}}):
            return site.id
        return None
    if site.id == "leetcode-leetcode-com":
        expected = {
            "query": "query userPublicProfile($username: String!) { matchedUser(username: $username) { username } }",
            "variables": {"username": "{username}"},
            "operationName": "userPublicProfile",
        }
        from .email_validation import _unique_object
        try:
            payload = json.loads(site.payload or "", object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return None
        if (site.url == "https://leetcode.com/u/{username}/"
                and site.url_probe == "https://leetcode.com/graphql/"
                and site.method == "POST" and site.id_type == "username"
                and not site.strip_chars and site.payload_format == "simple"
                and site.headers == {"Content-Type": "application/json"} and payload == expected):
            return site.id
        return None
    routes = {
        "xnxx-porn-maker": ("https://www.xnxx.com/porn-maker/{username}", None),
        "xnxx-pornstars": ("https://www.xnxx.com/pornstar/{username}", None),
        "xnxx-xnxx-com": ("https://www.xnxx.com/profile/{username}", None),
        "twitter-x": ("https://twitter.com/{username}", "https://syndication.twitter.com/srv/timeline-profile/screen-name/{username}"),
        "twittercommunity-com": ("https://twittercommunity.com/u/{username}", None),
        "twitter-archived-profile": ("https://web.archive.org/web/2/https://twitter.com/{username}", "http://archive.org/wayback/available?url=https://twitter.com/{username}"),
        "twitter-archived-tweets": ("https://web.archive.org/web/*/https://twitter.com/{username}/status/*", "http://archive.org/wayback/available?url=https://twitter.com/{username}/status/*"),
        "youporn-pornstars": ("https://www.youporn.com/pornstar/{username}/", None),
        "youporn-channels": ("https://www.youporn.com/channel/{username}/", None),
        "xvideos-pornstars": ("https://www.xvideos.com/pornstars/{username}", None),
        "xvideos-users-channels": ("https://www.xvideos.com/{username}", None),
        "xvideosmodels": ("https://www.xvideos.com/models/{username}", None),
        "xvideos-red": ("https://www.xvideos.red/{username}", None),
        "xvideos": ("https://www.xvideos.com/profiles/{username}", "https://www.xvideos.com/profiles/{username}/feed/"),
        "stripchat": ("https://stripchat.com/{username}", "https://stripchat.com/api/front/users/checkUsername?username={username}"),
        "spankbang": ("https://spankbang.com/p/{username}", None),
        "erome": ("https://www.erome.com/{username}", None),
        "e621": ("https://e621.net/users/{username}", None),
        "adultism": ("https://www.adultism.com/profile/{username}", None),
        "tiktok": ("https://www.tiktok.com/@{username}", None),
        "tiktok-tiktok-com": ("https://www.tiktok.com/@{username}?lang=en", "https://www.tiktok.com/oembed?url=https://www.tiktok.com/@{username}"),
        "youtube": ("https://www.youtube.com/@{username}/about", None),
        "x": ("https://x.com/{username}", "https://api.x.com/i/users/username_available.json?username={username}"),
        "tumblr-tumblr-com": ("https://www.tumblr.com/{username}", None),
        "gravatar-gravatar-com": ("https://gravatar.com/{username}", None),
        "sports-tracker": ("https://sports-tracker.com/view_profile/{username}", "https://api.sports-tracker.com/apiserver/v1/user/name/{username}"),
        "fotka-fotka-com": ("https://fotka.com/profil/{username}", "https://api.fotka.com/v2/user/dataStatic?login={username}"),
        "pr0gramm": ("https://pr0gramm.com/user/{username}", "https://pr0gramm.com/api/profile/info?name={username}"),
        "livejournal": ("https://{username}.livejournal.com", None),
        "tenor": ("https://tenor.com/users/{username}", None),
        "giphy": ("https://giphy.com/{username}", None),
        "giphy-channel": ("https://giphy.com/channel/{username}", None),
        "discord-invite": ("https://discord.com/invite/{username}", "https://discord.com/api/v9/invites/{username}?with_counts=true&with_expiration=true"),
        "clubhouse": ("https://www.clubhouse.com/@{username}", None),
        "aparat": ("https://www.aparat.com/{username}", "https://www.aparat.com/api/fa/v1/user/user/information/username/{username}"),
        "vinted": ("https://www.vinted.com/member/{username}", None),
        "themeforest": ("https://themeforest.net/user/{username}", None),
        "pastebin": ("https://pastebin.com/u/{username}", None),
        "omg-lol": ("https://{username}.omg.lol", "https://api.omg.lol/address/{username}/info"),
        "freelancer": ("https://www.freelancer.com/u/{username}", "https://www.freelancer.com/api/users/0.1/users?usernames%5B%5D={username}&compact=true"),
        "stats-fm": ("https://stats.fm/{username}", "https://api.stats.fm/api/v1/users/{username}"),
        "mixcloud": ("https://www.mixcloud.com/{username}/", "https://api.mixcloud.com/{username}/"),
        "bandlab-bandlab-com": ("https://www.bandlab.com/{username}", "https://www.bandlab.com/api/v1.3/users/{username}"),
        "vimeo": ("https://vimeo.com/{username}", None),
        "twitch": ("https://twitch.tv/{username}/", "https://twitchtracker.com/{username}"),
        "taplink": ("https://taplink.cc/{username}", None),
        "substack": ("https://{username}.substack.com/", None),
        "substack-substack-com": ("https://substack.com/@{username}", "https://substack.com/api/v1/user/{username}/public_profile"),
        "solo-to": ("https://solo.to/{username}", None),
        "medium": ("https://medium.com/@{username}", "https://medium.com/feed/@{username}"),
        "medium-medium-com": ("https://medium.com/@{username}/about", None),
        "lnk-bio": ("https://lnk.bio/{username}", None),
        "boosty": ("https://boosty.to/{username}", "https://api.boosty.to/v1/blog/{username}"),
        "linktree": ("https://linktr.ee/{username}", None),
        "bio-site": ("https://bio.site/{username}", None),
        "fansly": ("https://apiv2.fansly.com/api/v1/account?usernames={username}", None),
        "fansly-fansly-com": ("https://fansly.com/{username}/posts", "https://apiv3.fansly.com/api/v1/account?usernames={username}"),
        "picsart": ("https://picsart.com/u/{username}", "https://api.picsart.com/users/show/{username}.json"),
        "flickr-albums": ("https://www.flickr.com/photos/{username}/albums", None),
        "35photo": ("https://35photo.pro/@{username}/", None),
        "unsplash": ("https://unsplash.com/@{username}", None),
        "myminifactory": ("https://www.myminifactory.com/users/{username}", None),
        "quora": ("https://www.quora.com/profile/{username}", None),
        "quora-com": ("https://www.quora.com/{username}", None),
        "academia": ("https://academia.edu/{username}", None),
        "d3ru": ("https://d3.ru/user/{username}/posts", None),
        "warframe-market": ("https://warframe.market/profile/{username}", "https://api.warframe.market/v2/user/{username}"),
        "monkeytype": ("https://monkeytype.com/profile/{username}", "https://api.monkeytype.com/users/{username}/profile"),
        "kick": ("https://kick.com/{username}", "https://kick.com/api/v2/channels/{username}"),
        "etoro": ("https://www.etoro.com/people/{username}", "https://www.etoro.com/api/logininfo/v1.1/users/{username}"),
        "fragment": ("https://fragment.com/username/{username}", None),
        "cropty": ("https://www.cropty.io/@{username}", "https://api.cropty.io/v1/auth/{username}"),
        "destream": ("https://destream.net/live/{username}", "https://api.destream.net/siteapi/v2/live/details/{username}"),
        "donatello": ("https://donatello.to/{username}", None),
        "ko-fi": ("https://ko-fi.com/{username}", None),
        "microsoft-learn": ("https://learn.microsoft.com/en-us/users/{username}/", "https://learn.microsoft.com/api/profiles/{username}"),
        "sourceforge": ("https://sourceforge.net/u/{username}", None),
        "sourceforge-sourceforge-net": ("https://sourceforge.net/u/{username}/profile", "https://sourceforge.net/rest/u/{username}/profile"),
        "npm": ("https://www.npmjs.com/~{username}", None),
        "wordpress-org-forums": ("https://wordpress.org/support/users/{username}/", "https://login.wordpress.org/wp-json/wporg/v1/username-available/{username}"),
        "devpost-com": ("https://devpost.com/{username}", None),
        "hackerone-com": ("https://hackerone.com/{username}?type=user", None),
        "hackerrank-hackerrank-com": ("https://www.hackerrank.com/profile/{username}", "https://www.hackerrank.com/rest/contests/master/hackers/{username}/profile"),
        "bugcrowd-bugcrowd-com": ("https://bugcrowd.com/h/{username}", "https://bugcrowd.com/profile-service/v1/profiles/{username}"),
        "codeforces": ("https://codeforces.com/profile/{username}", "https://codeforces.com/api/user.info?handles={username}"),
        "github-gists": ("https://gist.github.com/{username}", "https://api.github.com/users/{username}/gists"),
        "wikipedia-en-wikipedia-org": ("https://en.wikipedia.org/wiki/User:{username}", "https://en.wikipedia.org/w/api.php?action=query&format=json&list=users&ususers={username}&usprop=cancreate&formatversion=2"),
        "chess-com": ("https://www.chess.com/member/{username}", "https://api.chess.com/pub/player/{username}"),
        "scratch": ("https://scratch.mit.edu/users/{username}/", "https://api.scratch.mit.edu/accounts/checkusername/{username}/"),
        "codewars": ("https://www.codewars.com/users/{username}", "https://www.codewars.com/api/v1/users/{username}"),
        "lichess-org": ("https://lichess.org/@/{username}", "https://lichess.org/api/player/autocomplete?term={username}&exists=1"),
        "artstation": ("https://www.artstation.com/{username}",
                       "https://www.artstation.com/api/v2/user_profiles/{username}.json"),
        "tryhackme": ("https://tryhackme.com/p/{username}",
                      "https://tryhackme.com/api/user/exist/{username}"),
        "tryhackme-tryhackme-com": ("https://tryhackme.com/r/p/{username}",
                                   "https://tryhackme.com/api/user/exist/{username}"),
    }
    if site.id not in routes or (site.url, site.url_probe) != routes[site.id]:
        return None
    if (site.id_type != "username" or site.method != "GET" or site.payload
            or (site.strip_chars and not ((site.id == "medium-medium-com" and site.strip_chars == ".")
                or (site.id == "omg-lol" and site.strip_chars == "@.")
                or (site.id in ("livejournal", "tumblr-tumblr-com") and site.strip_chars == ".")))
            or any(key.lower() not in {"accept", "accept-language", "user-agent"} for key in site.headers)):
        return None
    if site.id in ("twitter-x", "twittercommunity-com", "twitter-archived-profile", "twitter-archived-tweets", "youporn-pornstars", "youporn-channels", "xvideos-pornstars", "xvideos-users-channels", "xvideosmodels", "xvideos-red", "xnxx-porn-maker", "xnxx-pornstars", "xnxx-xnxx-com", "xvideos", "stripchat", "spankbang", "erome", "e621", "adultism", "tiktok", "tiktok-tiktok-com", "youtube", "x", "tumblr-tumblr-com", "tenor", "livejournal", "pr0gramm", "fotka-fotka-com", "sports-tracker", "gravatar-gravatar-com", "giphy", "giphy-channel", "discord-invite", "clubhouse", "aparat", "vinted", "themeforest", "pastebin", "omg-lol", "freelancer", "stats-fm", "mixcloud", "bandlab-bandlab-com", "vimeo", "twitch", "taplink", "substack", "substack-substack-com", "solo-to", "medium", "medium-medium-com", "lnk-bio", "boosty", "linktree", "bio-site", "fansly", "fansly-fansly-com", "picsart", "flickr-albums", "35photo", "unsplash", "myminifactory", "quora", "quora-com", "academia", "d3ru", "warframe-market", "monkeytype", "kick", "etoro", "fragment", "cropty", "destream", "donatello", "ko-fi", "microsoft-learn", "sourceforge", "sourceforge-sourceforge-net", "npm", "wordpress-org-forums", "devpost-com", "hackerone-com", "hackerrank-hackerrank-com", "bugcrowd-bugcrowd-com", "codeforces", "codewars", "lichess-org", "chess-com", "scratch", "wikipedia-en-wikipedia-org", "github-gists"):
        return site.id
    return "artstation" if site.id == "artstation" else "tryhackme-exists"


def outcome(kind, code, text, query, headers):
    if kind == "twitter-x":
        from .twitter_timeline_contracts import outcome as timeline_outcome
        return timeline_outcome(code, text, query, headers)
    if kind == "twittercommunity-com":
        from .discourse_contracts import catalogue_outcome
        return catalogue_outcome(code, text, query, headers)
    if kind in ("twitter-archived-profile", "twitter-archived-tweets"):
        from .twitter_archive_contracts import outcome as archive_outcome
        return archive_outcome(code, text, query, headers, kind == "twitter-archived-tweets")
    if kind == "stripchat":
        from .stripchat_contracts import availability
        return availability(code, text, query, headers)
    issue, note = http_issue(code, headers, text, accepted=(200, 404))
    if issue is not None:
        return issue, {}, note
    if kind in ("xnxx-porn-maker", "xnxx-pornstars", "xnxx-xnxx-com"):
        import httpx

        from .xnxx_contracts import public_profile
        parsed = public_profile(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind in ("youporn-pornstars", "youporn-channels"):
        import httpx

        from .youporn_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query,
                        "pornstar" if kind == "youporn-pornstars" else "channel")
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.is_found() else Status.UNKNOWN), fields, parsed.reason
    if kind in ("xvideos", "xvideos-pornstars", "xvideos-users-channels", "xvideosmodels", "xvideos-red"):
        import httpx

        from .xvideos_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query, "profile" if kind == "xvideos" else kind)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "spankbang":
        import httpx

        from .spankbang_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "erome":
        import httpx

        from .erome_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "e621":
        import httpx

        from .e621_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "adultism":
        import httpx

        from .adultism_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "bdsmlr":
        import httpx

        from .bdsmlr_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind in ("tiktok", "tiktok-tiktok-com"):
        import httpx

        from .tiktok_contracts import oembed
        parsed = oembed(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "youtube":
        import httpx

        from .youtube_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "x":
        import httpx

        from .x_contracts import availability
        parsed = availability(httpx.Response(code, text=text, headers=headers), query)
        state = {"TAKEN": Status.FOUND, "AVAILABLE": Status.NOT_FOUND}.get(parsed.status.name, Status.UNKNOWN)
        return state, dict(parsed.extra), parsed.reason
    if kind == "tumblr-tumblr-com":
        import httpx

        from .tumblr_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "bitchute":
        import httpx

        from .bitchute_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "tenor":
        import httpx

        from .tenor_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "livejournal":
        import httpx

        from .livejournal_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "pr0gramm":
        import httpx

        from .pr0gramm_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "fotka-fotka-com":
        import httpx

        from .fotka_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "sports-tracker":
        import httpx

        from .sportstracker_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "gravatar-gravatar-com":
        import httpx

        from .gravatar_username_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind in ("giphy", "giphy-channel"):
        import httpx

        from .giphy_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind in ("discord", "discord-invite"):
        import httpx

        from .discord_contracts import availability, invite
        parsed = (availability if kind == "discord" else invite)(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.NOT_FOUND if parsed.status.name == "AVAILABLE" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind in ("medium", "medium-medium-com"):
        import httpx

        from .medium_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query, "feed" if kind == "medium" else "html_about")
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "kick":
        import httpx

        from .kick_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.NOT_FOUND if parsed.status.name == "AVAILABLE" else Status.UNKNOWN), fields, parsed.reason
    if kind == "monkeytype":
        import httpx

        from .monkeytype_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "warframe-market":
        import httpx

        from .warframe_market_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "d3ru":
        import httpx

        from .d3_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "academia":
        import httpx

        from .academia_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query, base_url="https://academia.edu")
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind in ("quora", "quora-com"):
        import httpx

        from .quora_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "myminifactory":
        import httpx

        from .myminifactory_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "unsplash":
        import httpx

        from .unsplash_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "35photo":
        import httpx

        from .photo35_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "flickr-albums":
        import httpx

        from .flickr_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.status.name == "TAKEN":
            fields["scope"] = "Matching Flickr owner on albums page; not proof of public albums"
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "picsart":
        import httpx

        from .picsart_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind in ("fansly", "fansly-fansly-com"):
        import httpx

        from .fansly_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.NOT_FOUND if parsed.status.name == "AVAILABLE" else Status.UNKNOWN), fields, parsed.reason
    if kind == "bio-site":
        import httpx

        from .bio_site_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "linktree":
        import httpx

        from .linktree_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "boosty":
        import httpx

        from .boosty_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "lnk-bio":
        import httpx

        from .lnkbio_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "solo-to":
        import httpx

        from .solo_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "taplink":
        import httpx

        from .taplink_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "bandlab-bandlab-com":
        import httpx

        from .bandlab_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "mixcloud":
        import httpx

        from .mixcloud_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "clubhouse":
        import httpx

        from .clubhouse_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "aparat":
        import httpx

        from .aparat_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "vinted":
        import httpx

        from .vinted_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query, "https://www.vinted.com")
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "themeforest":
        import httpx

        from .themeforest_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "pastebin":
        import httpx

        from .pastebin_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "omg-lol":
        import httpx

        from .omglol_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "freelancer":
        import httpx

        from .freelancer_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind == "stats-fm":
        import httpx

        from .statsfm_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "twitch":
        import httpx

        from .twitchtracker_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "vimeo":
        import httpx

        from .vimeo_contracts import page_result as result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "substack-substack-com":
        import httpx

        from .substack_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "substack":
        import httpx

        from .substack_contracts import publication_result as result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "etoro":
        import httpx

        from .etoro_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "fragment":
        import httpx

        from .fragment_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind in ("cropty", "destream"):
        import httpx

        from .finance_user_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), kind, query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind in ("donatello", "ko-fi"):
        import httpx

        from .donation_page_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), "kofi" if kind == "ko-fi" else kind, query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "microsoft-learn":
        import httpx

        from .microsoft_learn_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), dict(parsed.extra), parsed.reason
    if kind in ("sourceforge", "sourceforge-sourceforge-net"):
        import httpx

        from .sourceforge_contracts import fields, profile
        data, reason = profile(httpx.Response(code, text=text, headers=headers), query)
        if data is None:
            return Status.UNKNOWN, {}, reason
        return Status.FOUND, fields(data), None
    if kind == "npm":
        import httpx

        from .npm_scope_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        status = {"TAKEN": Status.FOUND, "AVAILABLE": Status.NOT_FOUND}.get(parsed.status.name, Status.UNKNOWN)
        return status, fields, parsed.reason
    if kind == "wordpress-org-forums":
        from .email_validation import _unique_object
        unknown = (Status.UNKNOWN, {}, "No coherent WordPress.org username-availability response")
        if code != 200:
            return unknown
        try:
            data = json.loads(text, object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return unknown
        if not isinstance(data, dict) or ("username" in data and not _matches(data["username"], query)):
            return unknown
        fields = {"scope": "WordPress.org username registration availability; not forum activity or ownership proof"}
        if data.get("available") is True and not has_service_error(data):
            return Status.NOT_FOUND, fields, None
        if (data.get("error") == "That username is already in use."
                and ("available" not in data or data["available"] is False)
                and not has_service_error({key: value for key, value in data.items() if key != "error"})):
            return Status.FOUND, fields, None
        return unknown
    if kind in ("devpost-com", "hackerone-com"):
        import httpx

        from .developer_page_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers),
                        "devpost" if kind == "devpost-com" else "hackerone", query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind == "hackerone":
        from .email_validation import _unique_object
        unknown = (Status.UNKNOWN, {}, "No coherent matching HackerOne user resource")
        if code != 200:
            return unknown
        try:
            data = json.loads(text, object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return unknown
        if not isinstance(data, dict) or has_service_error(data):
            return unknown
        envelope = data.get("data")
        if not isinstance(envelope, dict) or has_service_error(envelope):
            return unknown
        record = envelope.get("resource")
        if not isinstance(record, dict) or has_service_error(record) or not _matches(record.get("username"), query):
            return unknown
        return Status.FOUND, {"username": record["username"]}, None
    if kind in ("bugcrowd-bugcrowd-com", "hackerrank-hackerrank-com"):
        import httpx

        from .developer_user_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers),
                        "hackerrank" if kind == "hackerrank-hackerrank-com" else "bugcrowd", query)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return (Status.FOUND if parsed.status.name == "TAKEN" else Status.UNKNOWN), fields, parsed.reason
    if kind in ("codeforces", "leetcode-leetcode-com"):
        import httpx

        from .coding_user_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers),
                        "leetcode" if kind == "leetcode-leetcode-com" else kind, query)
        state = {"TAKEN": Status.FOUND, "AVAILABLE": Status.NOT_FOUND}.get(parsed.status.name, Status.UNKNOWN)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return state, fields, parsed.reason
    if kind == "github-gists":
        from .email_validation import _unique_object
        unknown = (Status.UNKNOWN, {}, "No bound public Gist evidence; an empty list does not establish account absence")
        if code != 200:
            return unknown
        try:
            rows = json.loads(text, object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            return unknown
        if not isinstance(rows, list) or not rows:
            return unknown
        owner_ids, gist_ids = set(), set()
        for row in rows:
            if not isinstance(row, dict) or has_service_error(row) or row.get("public") is not True:
                return unknown
            owner, gist_id = row.get("owner"), row.get("id")
            if (not isinstance(owner, dict) or has_service_error(owner) or not _matches(owner.get("login"), query)
                    or type(owner.get("id")) is not int or owner["id"] <= 0
                    or not isinstance(gist_id, str) or not re.fullmatch(r"[0-9a-fA-F]{1,64}", gist_id)):
                return unknown
            owner_ids.add(owner["id"])
            gist_ids.add(gist_id)
        if len(owner_ids) != 1 or len(gist_ids) != len(rows):
            return unknown
        return Status.FOUND, {"scope": "Public Gists returned for this username; not ownership proof",
                              "public_gists_on_page": len(rows), "owner_id": next(iter(owner_ids))}, None
    if kind == "wikipedia-en-wikipedia-org":
        import httpx

        from .wiki_user_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), query, "wikipedia")
        state = {"TAKEN": Status.FOUND, "AVAILABLE": Status.NOT_FOUND}.get(parsed.status.name, Status.UNKNOWN)
        return state, parsed.extra, parsed.reason
    if kind in ("codewars", "chess-com"):
        import httpx

        from .named_user_contracts import result
        parsed = result(httpx.Response(code, text=text, headers=headers), "chess_com" if kind == "chess-com" else kind, query)
        state = {"TAKEN": Status.FOUND, "AVAILABLE": Status.NOT_FOUND}.get(parsed.status.name, Status.UNKNOWN)
        fields = dict(parsed.extra)
        if parsed.media:
            fields["media"] = parsed.media
        return state, fields, parsed.reason
    if kind == "lichess-org":
        if code == 200 and text.strip() in ("true", "false"):
            return (Status.FOUND if text.strip() == "true" else Status.NOT_FOUND), {}, None
        return Status.UNKNOWN, {}, "No literal boolean username-existence response"
    if kind == "scratch":
        from .email_validation import _unique_object
        try:
            data = json.loads(text, object_pairs_hook=_unique_object)
        except (TypeError, ValueError):
            data = None
        if (code == 200 and isinstance(data, dict) and not has_service_error(data)
                and ("username" not in data or _matches(data["username"], query))):
            if data.get("msg") == "username exists":
                return Status.FOUND, {}, None
            if data.get("msg") == "valid username":
                return Status.NOT_FOUND, {}, None
        return Status.UNKNOWN, {}, "No coherent username-availability response"
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        data = None
    unknown = (Status.UNKNOWN, {}, "Response does not establish an unambiguous result for the requested username")
    if not isinstance(data, dict):
        return unknown
    if kind == "artstation":
        if code == 404:
            message = data.get("message")
            # The shipped catalogue's missing-user marker, additionally bound
            # to this query and incompatible with simultaneous profile fields.
            if (isinstance(message, str) and re.match(
                    r"User with username:\s*['\"]?" + re.escape(query) + r"(?:['\"]|\s|$)", message, re.I)
                    and not any(key in data for key in ("id", "username", "full_name"))
                    and not has_service_error(data)):
                return Status.NOT_FOUND, {}, None
            return unknown
        if (has_service_error(data) or data.get("message") or type(data.get("id")) is not int or data["id"] <= 0
                or not _matches(data.get("username"), query)):
            return unknown
        fields = _strings(data, {"full_name": "name", "headline": "headline", "city": "city", "country": "country"})
        if type(data.get("followers_count")) is int and data["followers_count"] >= 0:
            fields["followers"] = str(data["followers_count"])
        if isinstance(data.get("large_avatar_url"), str) and data["large_avatar_url"].strip():
            fields["media"] = {"avatar": data["large_avatar_url"]}
        return Status.FOUND, fields, None
    if kind == "tryhackme-exists":
        rest = {key: value for key, value in data.items() if key != "success"}
        if (code != 200 or type(data.get("success")) is not bool or has_service_error(rest)
                or data.get("message") or data.get("data")
                or ("username" in data and not _matches(data["username"], query))):
            return unknown
        return (Status.FOUND if data["success"] else Status.NOT_FOUND), {}, None
    if kind != "tryhackme-profile" or code != 200:
        return unknown
    profile = data.get("data")
    if (data.get("status") == "error" and data.get("message") == "Profile not found"
            and profile in (None, {}) and not has_service_error({key: value for key, value in data.items() if key != "status"})):
        return Status.NOT_FOUND, {}, None
    if (data.get("status") != "success" or has_service_error(data) or data.get("message")
            or not isinstance(profile, dict) or not _matches(profile.get("username"), query)
            or has_service_error(profile)):
        return unknown
    fields = _strings(profile, {"country": "country"})
    for source, target in {"level": "level", "totalPoints": "points", "rank": "rank",
                           "completedRoomsNumber": "rooms_completed", "streak": "streak"}.items():
        if type(profile.get(source)) is int and profile[source] >= 0:
            fields[target] = profile[source]
    if isinstance(profile.get("avatar"), str) and profile["avatar"].strip():
        fields["media"] = {"avatar": profile["avatar"]}
    return Status.FOUND, fields, None


def _matches(value, query):
    return isinstance(value, str) and bool(value) and value.casefold() == query.casefold()


def _strings(data, mapping):
    return {target: data[source] for source, target in mapping.items()
            if isinstance(data.get(source), str) and data[source].strip()}


def native_result(kind, response, query):
    from consensus_osint.vendor.user_scanner.core.result import Result

    status, fields, note = outcome(kind, response.status_code, response.text, query, response.headers)
    if status is Status.FOUND:
        media = fields.pop("media", {})
        return Result.taken(extra=fields, media=media)
    if status is Status.NOT_FOUND:
        return Result.available()
    return Result.error(note)
