import json

import httpx
from bs4 import BeautifulSoup

from consensus_osint.core.email_validation import _unique_object
from consensus_osint.core.mailbox_contracts import http_issue, valid_token
from consensus_osint.core.provider_contracts import has_service_error
from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.result import Result


async def _check(email: str) -> Result:
    show_url = "https://stackb.net"
    login_url = f"{show_url}/login"
    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en-US;q=0.9,en;q=0.8",
    }

    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            headers=headers,
            follow_redirects=True,
        ) as client:
            login_response = await client.get(login_url, follow_redirects=False)
            issue, reason = http_issue(login_response.status_code, login_response.headers, login_response.text)
            if issue is not None:
                return Result.error(reason, url=show_url)
            page = BeautifulSoup(login_response.text, "html.parser")
            for inert in page.select("script, style, template, noscript"):
                inert.decompose()
            tokens = page.find_all("meta", attrs={"name": "csrf-token"})
            forms = [tag for tag in page.find_all("div", attrs={"wire:snapshot": True, "wire:id": True})
                     if isinstance(tag.get("x-data"), str) and tag["x-data"].startswith("loginFormCaptcha")]
            csrf_token = tokens[0].get("content") if len(tokens) == 1 else None
            if not valid_token(csrf_token) or len(forms) != 1:
                return Result.error("Missing or ambiguous login form tokens", url=show_url)
            snapshot = forms[0].get("wire:snapshot")
            if not isinstance(snapshot, str) or len(snapshot) > 65536:
                return Result.error("Invalid login snapshot", url=show_url)
            state = json.loads(snapshot, object_pairs_hook=_unique_object)
            memo = state.get("memo") if isinstance(state, dict) else None
            if not isinstance(memo, dict) or memo.get("id") != forms[0]["wire:id"] or not valid_token(memo.get("id")):
                return Result.error("Unbound login snapshot", url=show_url)
            payload = {
                "_token": csrf_token,
                "components": [
                    {
                        "snapshot": snapshot,
                        "updates": {
                            "identifier": email,
                            "password": "StackB-not-the-password-12345",
                        },
                        "calls": [
                            {"path": "", "method": "submitLogin", "params": []}
                        ],
                    }
                ],
            }
            login_check = await client.post(
                f"{show_url}/livewire/update",
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": show_url,
                    "Referer": login_url,
                    "X-CSRF-TOKEN": csrf_token,
                    "X-Livewire": "true",
                },
                json=payload, follow_redirects=False,
            )

            issue, reason = http_issue(login_check.status_code, login_check.headers, login_check.text)
            if issue is not None:
                return Result.error(reason, url=show_url)
            data = json.loads(login_check.text, object_pairs_hook=_unique_object)
            def coherent(record):
                return isinstance(record, dict) and not has_service_error(record) and all(
                    key not in record or isinstance(record[key], str) and record[key].casefold() == email.casefold()
                    for key in ("email", "identifier"))
            if not coherent(data):
                return Result.error("Invalid login response", url=show_url)
            components = data.get("components")
            if not isinstance(components, list) or len(components) != 1 or not coherent(components[0]):
                return Result.error("Ambiguous login components", url=show_url)
            effects = components[0].get("effects")
            if not coherent(effects):
                return Result.error("Invalid login effects", url=show_url)
            dispatches = effects.get("dispatches")
            if not isinstance(dispatches, list) or len(dispatches) != 1 or not coherent(dispatches[0]):
                return Result.error("Ambiguous login dispatches", url=show_url)
            params = dispatches[0].get("params")
            if not coherent(params):
                return Result.error("Invalid login message", url=show_url)
            if params.get("message") == '\u0422\u0430\u043a\u0438\u0445 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u0439 \u043d\u0435 \u043d\u0430\u0448\u043b\u043e\u0441\u044c':
                return Result.available(url=show_url)
            return Result.error("No explicit missing-user response; wrong password does not prove an account", url=show_url)
    except Exception as exc:
        return Result.error(exc, url=show_url)


async def validate_stackb(email: str) -> Result:
    return await _check(email)
