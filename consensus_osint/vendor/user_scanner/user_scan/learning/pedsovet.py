import html
import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from consensus_osint.core.mailbox_contracts import http_issue

from consensus_osint.vendor.user_scanner.core.helpers import get_random_user_agent
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate
from consensus_osint.vendor.user_scanner.core.result import Result


def validate_pedsovet(user: str) -> Result:
    url = f"https://pedsovet.su/index/8-0-{user}"

    if not re.fullmatch(r"[a-z0-9_@]+", user, re.IGNORECASE):
        return Result.error(
            "Usernames can only contain letters, numbers, underscores and at signs",
            url=url,
        )

    headers = {
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ru,en-US;q=0.9,en;q=0.8",
    }

    def process(response):
        response_text = response.text
        issue, reason = http_issue(response.status_code, response.headers, response_text)
        if issue is not None:
            return Result.error(reason)

        logins = re.findall(r"<p>Логин:\s*([^<]+)</p>", response_text, re.IGNORECASE)
        if len(logins) > 1:
            return Result.error("Multiple profile login fields; query binding is ambiguous")
        found_login = html.unescape(logins[0]).strip() if logins else None

        if "Пользователь не найден" in response_text:
            return Result.error("Conflicting profile and missing-user evidence") if found_login else Result.available()

        if (
            found_login
            and found_login.lower() == user.lower()
            and "Ссылка на профиль:" in response_text
        ):
            extra = {"login": found_login}
            media = {}

            # A navigation link can name a different member. Only the labelled
            # profile field belongs to the login established above.
            candidates = set()
            soup = BeautifulSoup(response_text, "html.parser")
            for paragraph in soup.find_all("p"):
                if not paragraph.get_text(" ", strip=True).startswith("Ссылка на профиль:"):
                    continue
                for link in paragraph.find_all("a", href=True):
                    try:
                        parsed = urlsplit(urljoin(url, link["href"]))
                        match = re.fullmatch(r"/index/8-([1-9]\d*)", parsed.path)
                        if (match and parsed.scheme == "https" and parsed.hostname == "pedsovet.su"
                                and not parsed.username and not parsed.password and parsed.port in (None, 443)):
                            candidates.add(match.group(1))
                    except ValueError:
                        continue
            if len(candidates) == 1:
                extra["id"] = candidates.pop()
                extra["profile_url"] = "https://pedsovet.su/index/8-" + extra["id"]
                extra["_profile_url_source"] = "resolved from labelled profile link"

            for label, key in (
                ("Группа пользователей", "group"),
                ("Регистрация", "registered"),
            ):
                if field_match := re.search(rf"<p>{re.escape(label)}:\s*(.*?)</p>", response_text, re.IGNORECASE | re.DOTALL):
                    value = re.sub(r"<[^>]+>", "", field_match.group(1))
                    extra[key] = html.unescape(value).strip()

            if last_login_match := re.search(r"Последний вход\s*([^<]+)", response_text, re.IGNORECASE):
                extra["last_login"] = html.unescape(last_login_match.group(1)).strip()

            if avatar_match := re.search(
                r'<div class="user">\s*<center><img\s+src="([^"]+)"', response_text, re.IGNORECASE
            ):
                avatar = html.unescape(avatar_match.group(1)).strip()
                if avatar.startswith("//"):
                    avatar = "https:" + avatar
                elif avatar.startswith("/"):
                    avatar = "https://pedsovet.su" + avatar
                media["avatar"] = avatar

            if about_match := re.search(
                r'<div class="osebe">О себе</div>.*?<p class="clr">(.*?)</p>', response_text, re.IGNORECASE | re.DOTALL
            ):
                about = re.sub(r"<[^>]+>", "", about_match.group(1))
                about = html.unescape(about).strip()
                if about != "Пользователь пока ничего не сообщил о себе.":
                    extra["about"] = about

            return Result.taken(extra=extra, media=media)

        return Result.error("Unexpected response body")

    return generic_validate(
        url,
        process,
        headers=headers,
        show_url=url,
        follow_redirects=True,
    )
