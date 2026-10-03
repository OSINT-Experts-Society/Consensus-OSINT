from urllib.parse import quote
from consensus_osint.vendor.user_scanner.core.orchestrator import generic_validate, Result
from consensus_osint.core.jobs_learning_contracts import outcome
from consensus_osint.core.models import Status


def validate_duolingo(user):
    url = "https://www.duolingo.com/2017-06-30/users"
    show_url = "https://www.duolingo.com/profile/" + quote(user, safe="")

    def process(response):
        status, fields, reason = outcome('duolingo', response, user, kind='username')
        if status is Status.FOUND:
            avatar = fields.pop('avatar', None)
            extra = {key: value for key, value in fields.items() if not isinstance(value, list)}
            return Result.taken(extra=extra, media={'avatar': avatar} if avatar else {})
        if status is Status.NOT_FOUND:
            return Result.available()
        return Result.error(reason)

    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    return generic_validate(url, process, show_url=show_url, headers=headers, params={"username": user})
