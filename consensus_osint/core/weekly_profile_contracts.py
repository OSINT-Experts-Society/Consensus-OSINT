"""Response boundaries for the October weekly intake's public checks."""
import json
import re
from urllib.parse import unquote, urlsplit

from .email_validation import _unique_object
from .html_evidence import mask_comments, mask_elements
from .mailbox_contracts import http_issue
from .provider_contracts import has_service_error
from .soundcloud_contracts import _Scripts


def checked_json(response, *, query=None, expected_error=None):
    issue, reason = http_issue(response.status_code, response.headers, response.text)
    if issue is not None:
        raise ValueError(reason)
    data = json.loads(response.text, object_pairs_hook=_unique_object)
    records = data if isinstance(data, list) else [data]
    for record in records:
        if not isinstance(record, dict):
            continue
        envelopes = [record]
        if isinstance(record.get('response'), dict):
            envelopes.append(record['response'])
        for envelope in envelopes:
            errors = dict(envelope)
            if expected_error is not None and errors.get('error') == expected_error:
                errors.pop('error')
            if has_service_error(errors):
                raise ValueError('Lookup contains conflicting error information')
            for field in ('username', 'email'):
                if query is not None and field in envelope and (
                    not isinstance(envelope[field], str) or envelope[field].casefold() != query.casefold()
                ):
                    raise ValueError('Lookup identity differs from the requested account')
    return data


def profile_markup(response, expected_url, *, redirect_path=None, scripts=False):
    """Validate response origin and keep only active markup/script evidence."""
    issue, reason = http_issue(response.status_code, response.headers, response.text, accepted=(200, 404))
    if issue is not None:
        raise ValueError(reason)
    actual, expected = urlsplit(str(response.url)), urlsplit(expected_url)
    paths = {unquote(expected.path).rstrip('/').casefold()}
    if redirect_path:
        paths.add(redirect_path.rstrip('/'))
    if (actual.scheme != expected.scheme or actual.netloc.casefold() != expected.netloc.casefold()
            or unquote(actual.path).rstrip('/').casefold() not in paths or actual.fragment):
        raise ValueError('Response URL differs from the requested profile')
    text = mask_comments(response.text)
    text = mask_elements(text, ('template', 'noscript', 'style'))
    if scripts:
        return _Scripts(text).scripts
    return mask_elements(text, ('script',))


def script_matches(pattern, scripts):
    """Read data markers outside JS comments, examples and regex literals.

    Reuse the retained lexical boundary approach, never executing JavaScript.
    Do not concatenate script elements: fragments must not manufacture a record.
    """
    quoted = r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`'''
    ignored = (r'//[^\n]*|/\*[\s\S]*?\*/|' + quoted
               + r'|/(?![*/])(?:\\.|[^/\\\r\n])+/[dgimsuvy]*')
    return [match for script in scripts
            for match in re.finditer(ignored + r'|(?P<evidence>' + pattern + ')', script, re.DOTALL)
            if match['evidence'] is not None]
