"""Guard music and shared sign-in lookup responses."""
import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue, valid_token
from .models import Status
from .provider_contracts import has_service_error


def document(response):
    issue, reason=http_issue(response.status_code,response.headers,response.text)
    if issue is not None:
        return None,(issue,{},reason)
    try:
        data=json.loads(response.text,object_pairs_hook=_unique_object)
    except (TypeError,ValueError):
        data=None
    return data,None


def coherent(data,email=None,exclude=()):
    return isinstance(data,dict) and not has_service_error({k:v for k,v in data.items() if k not in exclude}) and (
        email is None or all(k not in data or isinstance(data[k],str) and data[k].casefold()==email.casefold() for k in ("email","EMAIL","identifier")))


def deezer_setup(response):
    data,issue=document(response)
    if issue is not None:
        return None,issue[2]
    if not coherent(data,exclude=("error",)) or data.get("error") not in (None,{},[]):
        return None,"Failed Deezer handshake"
    results=data.get("results")
    token=results.get("checkForm") if coherent(results) else None
    return (token,None) if valid_token(token) else (None,"Missing or invalid Deezer token")


def outcome(response,site,email):
    data,issue=document(response)
    if issue is not None:
        return issue
    unknown=(Status.UNKNOWN,{},"No coherent account lookup response")
    excluded=("status",) if site=="jiosaavn" else ("error",) if site=="deezer" else ()
    if not coherent(data,email,excluded):
        return unknown
    if site=="deezer":
        if data.get("error") not in (None,{},[]):
            return unknown
        results=data.get("results")
        if not coherent(results,email,("errors",)) or not isinstance(results.get("errors"),dict):
            return unknown
        errors=results["errors"]
        if not errors:
            return Status.NOT_FOUND,{},None
        record=errors.get("email")
        if set(errors)=={"email"} and coherent(record,None,("error",)) and record.get("error")=="email_already_used":
            return Status.FOUND,{},None
    elif site in ("gaana","indiatimes"):
        record=data.get("data")
        if data.get("status")!="SUCCESS" or not coherent(record,email):
            return unknown
        status=record.get("status")
        if status in ("VERIFIED_EMAIL","UNVERIFIED_EMAIL","UNREGISTERED_EMAIL"):
            extra={"scope":"Times Internet shared sign-in identity; does not establish use of this individual service"}
            if status=="UNVERIFIED_EMAIL":
                extra["email_verification"]="unverified"
            return (Status.NOT_FOUND if status=="UNREGISTERED_EMAIL" else Status.FOUND),extra,None
    elif site in ("jiosaavn","foxnews"):
        flag=data.get("status" if site=="jiosaavn" else "found")
        if type(flag) is bool:
            extra={"scope":"Fox shared sign-in identity; does not establish Fox News activity"} if site=="foxnews" else {}
            return (Status.FOUND if flag else Status.NOT_FOUND),extra,None
    return unknown
