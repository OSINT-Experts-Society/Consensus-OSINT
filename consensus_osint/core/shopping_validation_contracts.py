"""Coherent shopping email-validation replies."""
import json

from .email_validation import _unique_object
from .mailbox_contracts import http_issue
from .models import Status
from .provider_contracts import has_service_error


def outcome(response,site,email):
    issue,reason=http_issue(response.status_code,response.headers,response.text)
    if issue is not None:
        return issue,{},reason
    unknown=(Status.UNKNOWN,{},"No coherent shopping account response")
    try:
        data=json.loads(response.text,object_pairs_hook=_unique_object)
    except (TypeError,ValueError):
        return unknown
    def coherent(record):
        return isinstance(record,dict) and not has_service_error(record) and (
            "email" not in record or isinstance(record["email"],str) and record["email"].casefold()==email.casefold())
    if not coherent(data):
        return unknown
    if site=="nykaaman":
        record=data.get("response")
        if not coherent(record):
            return unknown
        exists=record.get("is_exists")
        message=record.get("message","")
        if type(exists) is not bool or not isinstance(message,str):
            return unknown
        if not exists and "already registered" in message.casefold() or exists and "welcome to nykaa" in message.casefold():
            return unknown
        return (Status.FOUND if exists else Status.NOT_FOUND),{},None
    user_type=data.get("userType")
    enrolled=data.get("emailEnrolled")
    if "emailEnrolled" in data and type(enrolled) is not bool:
        return unknown
    if user_type not in (None,"new","existing","migrated"):
        return unknown
    positive=user_type in ("existing","migrated") or enrolled is True
    negative=user_type=="new" or data.get("message")=="User is not found"
    if positive and (negative or enrolled is False):
        return unknown
    if not positive and not negative:
        return unknown
    extra={"scope":"Tata Digital shared sign-in identity; not evidence of Tata CLiQ activity"}
    for key,label,kind in (("userType","user_type",str),("emailEnrolled","email_enrolled",bool),("emailVerified","email_verified",bool),("phoneMasked","phone_masked",str)):
        if type(data.get(key)) is kind:
            extra[label]=data[key]
    return (Status.FOUND if positive else Status.NOT_FOUND),extra,None
