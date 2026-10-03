"""Bound login setup and coherent BBC/NYTimes validation responses."""
import html
import json
import re
from urllib.parse import parse_qs, urljoin, urlsplit

from bs4 import BeautifulSoup

from .email_validation import _unique_object
from .mailbox_contracts import http_issue, valid_token
from .models import Status
from .provider_contracts import has_service_error


async def setup(client, url, headers, site):
    origin=urlsplit(url)
    current=url
    for _attempt in range(4):
        response=await client.get(current,headers=headers,follow_redirects=False)
        if response.status_code in (301,302,303,307,308):
            location=response.headers.get("location")
            if not location:
                return None,"Login redirect lacks a destination"
            target=urlsplit(urljoin(current,location))
            if (target.scheme,target.netloc)!=(origin.scheme,origin.netloc) or target.username or target.password:
                return None,"Login redirect leaves the provider origin"
            current=target.geturl()
            continue
        issue,reason=http_issue(response.status_code,response.headers,response.text)
        if issue is not None:
            return None,reason
        values=[]
        if site=="bbc":
            values=parse_qs(urlsplit(current).query,keep_blank_values=True).get("nonce",[])
            if values:
                return (values[0],None) if len(values)==1 and valid_token(values[0]) else (None,"Ambiguous login nonce")
        field="nonce" if site=="bbc" else "authToken"
        page=BeautifulSoup(response.text,"html.parser")
        for script in page.find_all("script"):
            if script.find_parent(["template","noscript"]):
                continue
            text=html.unescape(script.get_text()).replace(chr(92) + chr(34), chr(34))
            values.extend(re.findall(r'"'+field+r'"\s*:\s*"([^"\\]+)"',text))
        return (values[0],None) if len(values)==1 and valid_token(values[0]) else (None,"Missing or ambiguous login token")
    return None,"Login redirect limit reached"


def outcome(response,site,email):
    issue,reason=http_issue(response.status_code,response.headers,response.text)
    if issue is not None:
        return issue,{},reason
    unknown=(Status.UNKNOWN,{},"No coherent email-bound account response")
    try:
        data=json.loads(response.text,object_pairs_hook=_unique_object)
    except (TypeError,ValueError):
        return unknown
    def coherent(record):
        return isinstance(record,dict) and not has_service_error(record) and all(
            key not in record or isinstance(record[key],str) and record[key].casefold()==email.casefold()
            for key in ("email","userIdentifier"))
    if not coherent(data):
        return unknown
    if site=="bbc":
        flag=data.get("exists")
        if type(flag) is bool:
            return (Status.FOUND if flag else Status.NOT_FOUND),{},None
        return unknown
    record=data.get("data")
    if not coherent(record):
        return unknown
    action=record.get("further_action")
    if action=="show-register":
        return Status.NOT_FOUND,{},None
    if action=="show-login":
        return Status.FOUND,{},None
    if action=="show-welcome-back":
        extra={"login_method":"SSO"}
        if isinstance(record.get("provider"),str):
            extra["sso_provider"]=record["provider"]
        if type(record.get("ssoMethodsCount")) is int and record["ssoMethodsCount"]>=0:
            extra["sso_methods"]=record["ssoMethodsCount"]
        return Status.FOUND,extra,None
    return unknown
