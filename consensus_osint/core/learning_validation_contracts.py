"""Strict validation and recovery evidence for learning providers."""
import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def outcome(response, site, email):
    accepted = {"programminghub": (200,400), "talkpal": (201,404), "heyjapan": (200,404)}.get(site,(200,))
    issue, reason = http_issue(response.status_code,response.headers,response.text,accepted=accepted)
    if issue is not None:
        return issue,{},reason
    unknown = (Status.UNKNOWN,{},"No coherent account-validation response; recovery acknowledgment alone is inconclusive")
    try:
        data=json.loads(response.text,object_pairs_hook=_unique_object)
    except (TypeError,ValueError):
        return unknown
    def coherent(record, exclude=()):
        return isinstance(record,dict) and not has_service_error({k:v for k,v in record.items() if k not in exclude}) and (
            "email" not in record or isinstance(record["email"],str) and record["email"].casefold()==email.casefold())
    if not coherent(data,("status",) if site=="programminghub" else ()):
        return unknown
    if site=="cakeapp":
        inner=data.get("data")
        if data.get("result")!="SUCCESS" or not coherent(inner):
            return unknown
        if inner.get("hasError") is False and inner.get("errorType") in (None,""):
            return Status.NOT_FOUND,{},None
        if inner.get("hasError") is True and inner.get("errorType")=="DUPLICATED":
            return Status.FOUND,{},None
    elif site in ("classdojo","vedantu"):
        flag=data.get("isAvailableForSignUp" if site=="classdojo" else "emailExists")
        if type(flag) is not bool:
            return unknown
        exists=not flag if site=="classdojo" else flag
        extra={}
        if exists and site=="vedantu" and isinstance(data.get("phone"),str):
            extra["phone"]=data["phone"]
        if exists and site=="classdojo":
            for source,target,kind in (("entityType","entity_type",str),("isPasswordless","is_passwordless",bool),("hasMandatorySSO","has_mandatory_sso",bool)):
                if type(data.get(source)) is kind:
                    extra[target]=data[source]
            providers=data.get("oidcProviders")
            if isinstance(providers,list) and providers and all(isinstance(p,str) for p in providers):
                extra["oidc_providers"]=providers
        return (Status.FOUND if exists else Status.NOT_FOUND),extra,None
    elif site=="programminghub":
        if response.status_code==400 and data.get("status") is False and data.get("message")=="You are not registered with us":
            return Status.NOT_FOUND,{},None
        record=data.get("data")
        if response.status_code==200 and data.get("status") is True and coherent(record):
            user_id=record.get("user_id")
            if type(user_id) is int and user_id>0 or isinstance(user_id,str) and user_id.strip() and not any(ord(c)<=32 for c in user_id):
                return Status.FOUND,{},None
    elif site=="talkpal":
        if response.status_code==404 and data.get("message")=="User not found" and type(data.get("statusCode")) is int and data["statusCode"]==404:
            return Status.NOT_FOUND,{},None
    elif site=="heyjapan":
        if response.status_code==404 and data.get("message")=="Email does not exist!":
            return Status.NOT_FOUND,{},None
    return unknown
