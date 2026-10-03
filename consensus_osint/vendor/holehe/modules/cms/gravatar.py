"""Legacy public-profile lookup; absence does not establish account absence."""
import hashlib


async def gravatar(email, client, out):
    name = "gravatar"
    domain = "en.gravatar.com"
    method = "other"
    result = dict(name=name, domain=domain, method=method, frequent_rate_limit=False,
                  rateLimit=False, exists=None, unknown=True,
                  reason="Unrecognised public-profile response")
    out.append(result)

    # This legacy endpoint uses MD5; normalise the address before hashing.
    hashed_name = hashlib.md5(email.strip().lower().encode()).hexdigest()
    response = await client.get(f"https://en.gravatar.com/{hashed_name}.json")
    result["http_status"] = response.status_code
    if response.status_code == 404:
        result.update(exists=False, unknown=False, reason=None)
        return
    if response.status_code != 200:
        result.update(rateLimit=response.status_code == 429,
                      blocked=response.status_code in (401, 403),
                      reason=f"Public-profile request returned HTTP {response.status_code}")
        return
    try:
        data = response.json()
    except ValueError:
        return
    entries = data.get("entry") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        return
    entry = entries[0]
    display_name, profile_url = entry.get("displayName"), entry.get("profileUrl")
    if not isinstance(display_name, str) or not isinstance(profile_url, str) or not profile_url.strip():
        return
    result.update(exists=True, unknown=False, reason=None,
                  others={"FullName": f"{display_name} / {profile_url}"})
