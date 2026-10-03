"""Human-facing interpretation and field grouping; never changes a verdict."""
from __future__ import annotations

import unicodedata
from datetime import datetime

from .models import INFO_CATEGORIES, Finding, Status, as_json_safe

_DIAGNOSTICS = frozenset({
    "exists", "registered", "available", "valid", "success", "reason", "error",
    "errormessage", "message", "status", "note", "attribution", "matched_by", "pgp_key",
})


def _diagnostic_field(key: str, value: object) -> bool:
    name = key.lower()
    # Some retained profile schemas use this name for a creation timestamp,
    # while checkers use it for a registration flag. Preserve both meanings.
    if name == "registered" and isinstance(value, str):
        # Retained Russian profile pages also return a dotted calendar date.
        # Keep its original text; recognizing a date is not locale conversion.
        if 8 <= len(value) <= 17 and "." in value:
            for pattern in ("%d.%m.%Y", "%d.%m.%Y, %H:%M"):
                try:
                    datetime.strptime(value, pattern)
                except ValueError:
                    continue
                return False
        if (10 <= len(value) <= 64 and value[4] == "-" and value[7] == "-"
                and (len(value) == 10 or value[10] in "Tt ")):
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
            else:
                return False
    return name in _DIAGNOSTICS


def split_fields(extra: object) -> tuple[dict, dict]:
    """Separate returned attributes from internal/operational metadata.

    Container names stay in keys to preserve provenance. An attribute here is a
    returned field, not a guarantee of enrichment, accuracy or email ownership.
    """
    details, diagnostics = {}, {}
    safe = as_json_safe(extra)
    if not isinstance(safe, dict):
        return details, diagnostics
    for raw_key, value in safe.items():
        key = str(raw_key)
        if value is None or value == "" or value == [] or value == {}:
            continue
        if key.lower() in ("others", "media") and isinstance(value, dict):
            child_details, child_diagnostics = split_fields(value)
            details.update({f"{key}.{k}": v for k, v in child_details.items()})
            diagnostics.update({f"{key}.{k}": v for k, v in child_diagnostics.items()})
        elif key.startswith("_") or _diagnostic_field(key, value):
            diagnostics[key] = value
        else:
            details[key] = value
    return details, diagnostics


def assessment(f: Finding) -> tuple[str, str, str]:
    """Label, explanation and visual tone, based on recorded evidence limits."""
    if f.category in INFO_CATEGORIES:
        if f.site_id == "email-local":
            return "Address and domain analysis", (
                "Consensus checks the email format and domain mail records using DNS and bundled provider lists. "
                "This does not check whether the mailbox or an account exists."), "info"
        if f.site_id == "phone-local":
            detail = "Country, number format and carrier information come from the offline phonenumbers database, not an owner lookup."
            if f.extra.get("online_allowed") is False:
                detail += " Online checks were not run: enter + and the country code, or supply --phone-region."
            return "Phone number analysis", detail, "info"
        if f.category == "dorks":
            return "Suggested search links", (
                "Consensus constructed these search links. The searches have not been run and are not account matches."), "info"
        return "Supporting information", (
            "Supporting information from the named source; this is not an account or identity match."), "info"
    labels = {
        Status.NOT_FOUND: ("No match", "This check reported no match within its supported scope.", "muted"),
        Status.UNKNOWN: ("Inconclusive", "The response did not establish a match or a genuine negative.", "warn"),
        Status.BLOCKED: ("Blocked", "A challenge or access restriction prevented a conclusion.", "warn"),
        Status.RATE_LIMITED: ("Rate limited", "The service limited requests; account state is unknown.", "warn"),
        Status.ERROR: ("Error", "The check failed; this is not evidence of account absence.", "bad"),
        Status.SKIPPED: ("Skipped", "This check was not run under the selected scope or policy.", "muted"),
    }
    extra = f.extra if isinstance(f.extra, dict) else {}
    lookup = extra.get("_lookup_query")
    normalisation = (f"This site's formatting rule changes the search value to {lookup!r}. "
                     "Any lookup conclusion applies to that value; confirm it is the identifier you intended to check."
                     if isinstance(lookup, str) and lookup != f.query else "")
    if f.site_id in ("us-user-email-protonmail", "us-user-learning-annaabi", "us-user-social-discord", "discord", "us-user-social-reddit", "us-user-social-x", "x", "stripchat", "us-user-adult-xnxx") and f.status is Status.NOT_FOUND:
        return "Username available", "Signup availability response; this does not establish a current account, public profile or mailbox ownership.", "info"
    if f.status is not Status.FOUND:
        if f.source == "phone" and f.category == "reputation" and f.status is Status.NOT_FOUND:
            return "No reputation records", ("The source reports no available reputation records for this number. "
                                              "This does not establish that it is inactive, unregistered or trustworthy."), "muted"
        label, explanation, tone = labels.get(f.status, labels[Status.UNKNOWN])
        return label, explanation + (" " + normalisation if normalisation else ""), tone
    if normalisation:
        return "Needs review", normalisation, "warn"
    if extra.get("_text_decoding"):
        return "Needs review", ("Some source text could not be decoded; affected characters were replaced. "
                                "Review the affected text at its source and confirm the fields before using them."), "warn"
    query_echo_required = not ((f.source == "rules" and f.query_type in ("email", "phone")
                                and extra.get("_positive_marker") is True)
                               or (f.site_id in ("x", "stripchat") and extra.get("available") is False
                                   and extra.get("scope") in ("Username availability; not proof of a current X profile or ownership", "Username availability; not proof of a current Stripchat profile or ownership")))
    if extra.get("_weak_rule") or (extra.get("_page_mentions_query") is False and query_echo_required):
        return "Needs review", ("The page did not provide strong query-specific evidence. Open the result and check "
                                "that it is the requested profile, rather than a login, landing or missing-page screen."), "warn"
    if extra.get("_consensus") == "name differs from majority":
        return "Needs review", ("The returned name differs from the name found on most other sites for this query. "
                                "Compare the names and profile details; this may be an alias, outdated information or another person."), "warn"
    scope = {
        "phone-ovh": ("Range listed", "The number fits a geographic zone listed by OVH. "
                      "This does not establish its current carrier, active service or owner."),
        "phone-numverify": ("Validation signal", "Numverify reports number-format and numbering-plan information. "
                            "This does not establish a registered account or owner."),
        "phone-abstractapi": ("Validation signal", "AbstractAPI reports phone-validation information. "
                              "This does not establish a registered account or owner."),
        "phone-googlecse": ("Search results", "Google returned pages for a phone-number search. "
                            "These are search leads; verify the number on each page before associating its content with the query."),
    }.get(f.site_id)
    if f.source == "phone" and f.category == "reputation":
        scope = ("Reputation signal", "The source reports ratings or reports linked to this phone number. "
                 "These are third-party claims; they do not establish the current owner's identity or verify a caller's behaviour.")
    scope_tone = "info"
    if f.site_id in ("us-user-email-protonmail", "us-user-learning-annaabi", "us-user-social-discord", "discord", "stripchat"):
        scope = ("Username unavailable", "Signup availability response; this does not establish a current account, public profile or mailbox ownership.")
    elif f.site_id == "us-user-social-reddit":
        scope = (("Profile found", "Reddit returned a matching profile; this does not establish ownership.")
                 if extra.get("profile_confirmed") is True else
                 ("Username unavailable", "Reddit reports the username unavailable; this does not establish a current account or explain why it is unavailable."))
    elif f.site_id == "rule-gravatar":
        scope = ("Public profile association", "Gravatar returned a profile bound to the email hash; this does not establish ownership or current activity.")
    elif f.site_id == "twitter-x":
        scope = ("Timeline author found", "X returned timeline data containing a matching author; this does not establish current profile availability or ownership.")
    elif f.site_id == "twittercommunity-com":
        scope = ("Forum profile found", "Twitter Community returned a matching forum profile; this does not establish a current X account or ownership.")
    elif f.site_id in ("twitter-archived-profile", "twitter-archived-tweets"):
        scope = ("Archived URL found", "Internet Archive reports a snapshot of the requested URL; this does not establish a real account, current activity or ownership.")
    elif f.site_id in ("us-user-adult-youporn", "youporn-pornstars", "youporn-channels"):
        scope = ("Public page found", "YouPorn returned a matching public page; this does not establish ownership or signup availability.")
    elif f.site_id in ("xvideos-pornstars", "xvideos-users-channels", "xvideosmodels", "xvideos-red"):
        scope = ("Creator page found", "XVideos returned a matching public creator page; this does not establish a same-named member account or ownership.")
    elif f.site_id == "us-user-adult-xnxx":
        scope = (("Public profile found", "XNXX returned a matching public profile; this does not establish ownership.")
                 if extra.get("profile_confirmed") is True else
                 ("Username unavailable", "XNXX reports this username unavailable; this does not establish a public profile or account type."))
    elif f.site_id == "us-user-adult-chaturbate":
        scope = (("Profile found", "Chaturbate returned a matching public profile; this does not establish ownership.")
                 if extra.get("profile_confirmed") is True else
                 ("Username unavailable", "Chaturbate reports this username unavailable; this does not establish a current public profile or ownership."))
    elif f.site_id == "us-user-adult-bentbox":
        scope = ("Creator page found", "BentBox returned a matching creator page; this does not establish ownership.")
    elif f.site_id == "us-user-adult-apclips":
        scope = ("Creator page found", "APClips returned a matching creator page; this does not establish ownership.")
    elif f.site_id in ("us-user-adult-bdsmlr", "bdsmlr"):
        scope = ("Blog found", "BDSMLR returned a matching blog; this does not establish account ownership.")
    elif f.site_id in ("tiktok", "tiktok-tiktok-com", "us-user-social-tiktok"):
        scope = ("Creator embed found", "TikTok returned a matching creator embed; this does not establish ownership.")
    elif f.site_id in ("us-user-social-youtube", "youtube"):
        scope = ("Channel found", "YouTube returned a channel matching the requested handle; this does not establish ownership.")
    elif f.site_id in ("us-user-social-x", "x"):
        scope = (("Third-party profile", "VXTwitter returned a matching profile; this does not establish current X access or ownership.")
                 if extra.get("profile_confirmed") is True else
                 ("Username unavailable", "X reports this username unavailable; this does not establish a current profile or ownership."))
    elif f.site_id == "us-user-social-facebook":
        scope = ("Public page found", "Facebook returned a matching public page, which may be a profile or Page; this does not establish ownership.")
    elif f.site_id in ("us-user-social-tumblr", "tumblr-tumblr-com"):
        scope = ("Blog found", "Tumblr returned a matching blog; this does not establish account ownership.")
    elif f.site_id == "us-user-political-naturalnews":
        scope = ("Author archive found", "NaturalNews returned a matching author archive; this does not establish a user account or ownership.")
    elif f.site_id in ("us-user-political-bitchute", "bitchute"):
        scope = ("Channel found", "BitChute returned a matching channel ID; this does not establish a same-named user account or ownership.")
    elif f.site_id == "discord-invite":
        scope = ("Invite found", "Discord returned a matching invite code; this does not establish a same-named user account or ownership.")
    elif f.site_id in ("extras-proton-pgp", "holehe-protonmail"):
        scope = ("Key signal", "Public-key lookup signal; this does not prove mailbox existence or ownership.")
    elif any(name in f.site_id for name in ("hudsonrock", "leakcheck", "proxynova", "xposedornot")):
        scope = ("Exposure signal", "Provider-reported exposure association; not current account ownership.")
        scope_tone = "warn"
    elif f.site_id in ("holehe-office365", "us-email-other-office365"):
        scope = ("Routing signal", "Autodiscover returned a service endpoint for the requested address. "
                 "This does not prove mailbox existence, ownership or a general Microsoft account.")
    if isinstance(f.confidence, (int, float)) and f.confidence < 0.75:
        test_guidance = ("Validate the supported signal with controlled positive and negative evidence before relying on it."
                         if scope else "Validate this check with known-positive and known-negative test "
                         f"{'numbers' if f.query_type == 'phone' else 'accounts'} you control before relying on it.")
        return "Needs review", ((scope[1] + " " if scope else "") +
                                "The stored evidence score is below the review threshold. This describes the strength of "
                                "the check, not the probability of identity. "
                                "Confirm that returned fields belong to the exact query. " + test_guidance), "warn"
    if scope:
        return scope[0], scope[1], scope_tone
    if f.site_id == "holehe-archive":
        return "Needs review", ("The signup form reports this value as a taken username, not a registered email. "
                                "Confirm the account is linked to the queried email before relying on this result."), "warn"
    if f.query_type == "username":
        return "Found", "The site reports an account or profile matching this username.", "ok"
    if f.query_type == "email":
        if extra.get("registered") is True:
            return "Found", "The service reports this email as registered.", "ok"
        return "Found", "An email-linked match was reported. Check the returned details for its account or profile scope.", "ok"
    if f.query_type == "phone":
        return "Found", "The source reports information associated with this phone number; the owner is not confirmed.", "ok"
    return "Found", ("The selected check returned a positive signal for this query. Ticks beside tool names "
                     "show recorded coverage, not independent successful checks. Verify the result's scope and query binding."), "ok"


def enrichment_fields(f: Finding) -> dict:
    """Attributes adding information, separate from the complete evidence display.

    Exact query echoes, serialization/redaction markers and nested operational
    flags add no enrichment. This does not establish provider provenance or
    identity binding; those limits still travel with the finding.
    """
    if f.status is not Status.FOUND or f.category in INFO_CATEGORIES:
        return {}
    echo = unicodedata.normalize("NFKC", f.query).strip().casefold()

    def useful(value):
        if isinstance(value, dict):
            return {key: filtered for key, child in value.items()
                    if not any(part.startswith("_") for part in key.split("."))
                    and not _diagnostic_field(key.rsplit(".", 1)[-1], child)
                    and (filtered := useful(child)) is not None}
        if isinstance(value, list):
            return [filtered for child in value if (filtered := useful(child)) is not None]
        if isinstance(value, str):
            text = unicodedata.normalize("NFKC", value).strip().casefold()
            if (not text or text == echo or text == "***" or text == "[integer too large]"
                    or text.startswith(("[unsupported ", "[circular", "[truncated", "[maximum depth]"))):
                return None
        return value

    returned = split_fields(f.extra)[0]
    if f.extra.get("_profile_url_source") == "constructed":
        returned = {key: value for key, value in returned.items()
                    if "".join(char for char in key.lower() if char.isalpha())
                    not in {"profileurl", "profilelink", "othersprofileurl"}}
    declared = f.extra.get("_page_metadata_fields")
    # The retained User Scanner Result supports scalar metadata only.
    if isinstance(declared, str):
        declared = declared.split(",")
    page_fields = {name for name in declared if isinstance(name, str)} if isinstance(declared, list) else set()
    fields = useful({key: value for key, value in returned.items() if key not in page_fields})

    def populated(value):
        if isinstance(value, dict):
            return any(populated(child) for child in value.values())
        if isinstance(value, list):
            return any(populated(child) for child in value)
        return value is not None

    return {key: value for key, value in fields.items() if populated(value)}


def has_details(f: Finding) -> bool:
    return bool(enrichment_fields(f))
