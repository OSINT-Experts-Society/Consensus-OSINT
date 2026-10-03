"""Substitute identifiers once, using the encoding of their request context."""
from __future__ import annotations

import json
import re
from string import Formatter
from urllib.parse import quote, quote_plus, unquote_plus, urlsplit

_PLACEHOLDER = re.compile(r"\{([A-Za-z][A-Za-z0-9_]*)\}")
_LINE_END = re.compile(r"[\r\n]")


def subdomain_label(value: str) -> str:
    """Encode one identifier as a DNS label without changing a URL's authority."""
    import httpx

    if (not isinstance(value, str) or not value
            or any(char in ":/@\\?#%[]" or ord(char) < 33 for char in value)):
        raise ValueError("This site requires a single hostname label")
    try:
        # Use the transport's IDNA rules: the stdlib's older codec changes ß
        # into ss, which would silently query a different hostname.
        host = httpx.URL("https://" + value + ".invalid").raw_host.decode("ascii")
    except (UnicodeError, ValueError, httpx.InvalidURL):
        raise ValueError("This identifier cannot be used as a hostname label") from None
    label = host.removesuffix(".invalid")
    if label == host:
        raise ValueError("This site requires a single hostname label")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
        raise ValueError("This site requires one hostname label: letters, digits or internal hyphens")
    return label


def graphql_url(url: str) -> bool:
    """Recognise explicit GraphQL endpoint names used by retained definitions."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False  # Let the HTTP layer classify malformed URLs.
    return (parts.hostname or "").lower().startswith("graphql.") or "graphql" in parts.path.lower().split("/")


def payload_format_for(definition: dict) -> str:
    """Recognize only the legacy Maigret signature that omitted its grammar."""
    if "payload_format" in definition:
        return definition["payload_format"]
    payload = definition.get("payload")
    if (definition.get("detect_source") == "maigret" and isinstance(payload, dict)
            and isinstance(payload.get("query"), str) and payload["query"].lstrip().startswith("{{")
            and graphql_url(definition.get("url_probe") or definition.get("url", ""))):
        return "maigret"
    return "simple"


def _block_string(document: str, start: int) -> tuple[str, int]:
    """Decode GraphQL block-string indentation before inserting identifier text."""
    chars, pos = [], start + 3
    while pos < len(document):
        if document.startswith('\\"""', pos):
            chars.append('"""')
            pos += 4
        elif document.startswith('"""', pos):
            lines = "".join(chars).replace("\r\n", "\n").replace("\r", "\n").split("\n")
            indents = [len(line) - len(line.lstrip(" \t")) for line in lines[1:] if line.strip(" \t")]
            if indents:
                indent = min(indents)
                lines = [lines[0], *(line[indent:] for line in lines[1:])]
            first, last = 0, len(lines)
            while first < last and not lines[first].strip(" \t"):
                first += 1
            while first < last and not lines[last - 1].strip(" \t"):
                last -= 1
            return "\n".join(lines[first:last]), pos + 3
        else:
            chars.append(document[pos])
            pos += 1
    raise ValueError("GraphQL template has an unterminated block string")


def substitute_graphql(document: str, mapping: dict) -> str:
    """Only StringValue tokens carry substitutions; fields/comments stay literal.

    This serialises string values, not a GraphQL schema or operation validator.
    Block strings become ordinary escaped strings to retain inserted whitespace.
    """
    decoder = json.JSONDecoder()
    output, pos, copied = [], 0, 0
    while pos < len(document):
        if document[pos] == "#":
            end = _LINE_END.search(document, pos)
            pos = end.start() if end else len(document)
        elif document[pos] == '"':
            if document.startswith('"""', pos):
                value, end = _block_string(document, pos)
            else:
                value, end = decoder.raw_decode(document, pos)
            output.extend((document[copied:pos], json.dumps(substitute(value, mapping))))
            pos = copied = end
        else:
            pos += 1
    output.append(document[copied:])
    return "".join(output)


def substitute(value, mapping: dict):
    """Preserve inserted text literally; it is never treated as another template."""
    if isinstance(value, str):
        return _PLACEHOLDER.sub(lambda match: mapping.get(match[1], match[0]), value)
    if isinstance(value, dict):
        return {key: substitute(item, mapping) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, mapping) for item in value]
    return value


def maigret_uses_username(payload) -> bool:
    """Upstream formats only top-level string values, not nested JSON values."""
    if not isinstance(payload, dict):
        return False
    try:
        return any(field == "username" for value in payload.values() if isinstance(value, str)
                   for _, field, _, _ in Formatter().parse(value))
    except ValueError:
        return True  # The checker reports malformed template syntax as an error.


def _maigret_format(value: str, username: str) -> str:
    for _, field, spec, conversion in Formatter().parse(value):
        if field is not None and (field != "username" or spec or conversion):
            raise ValueError("Maigret payload supports only {username}, without conversions or format specifications")
    return value.format(username=username)


def _maigret_payload(payload, mapping: dict, graphql: bool):
    """Retain upstream's shallow format grammar while escaping inner GraphQL values."""
    if not isinstance(payload, dict):
        raise ValueError("Maigret payload must be an object")
    out = dict(payload)
    username = mapping.get("username", "{username}")
    for key, value in payload.items():
        if not isinstance(value, str):
            continue
        if key == "query" and graphql:
            # Normalize string escapes before selecting a slot, so an escaped
            # literal such as \u0043onsensusInputSlot0 cannot collide with it.
            normalized = substitute_graphql(value, {})
            index = 0
            while True:
                slot = f"ConsensusInputSlot{index}"
                token = "{" + slot + "}"
                if token not in normalized and token not in username:
                    break
                index += 1
            operation = _maigret_format(value, token)
            out[key] = substitute_graphql(operation, {slot: username})
            if token in out[key]:
                raise ValueError("GraphQL username placeholders must occur inside string values")
        else:
            out[key] = _maigret_format(value, username)
    return out


def substitute_url(value: str, mapping: dict) -> str:
    escaped = {key: quote(item, safe="") for key, item in mapping.items()}
    base, fragment_marker, fragment = value.partition("#")
    base, query_marker, query = base.partition("?")
    if not query_marker:
        return substitute(value, escaped)
    graphql = graphql_url(base)
    parts = []
    for part in query.split("&"):
        key, separator, raw = part.partition("=")
        decoded = unquote_plus(raw)
        if graphql and unquote_plus(key) == "query":
            raw = quote(substitute_graphql(decoded, mapping), safe="")
        elif any(match[1] in mapping for match in _PLACEHOLDER.finditer(decoded)):
            try:
                parsed = json.loads(decoded)
            except ValueError:
                raw = substitute(raw, escaped)
            else:
                raw = quote(json.dumps(substitute(parsed, mapping), ensure_ascii=False, separators=(",", ":")), safe="")
        else:
            raw = substitute(raw, escaped)
        parts.append(substitute(key, escaped) + separator + raw)
    return substitute(base, escaped) + query_marker + "&".join(parts) + fragment_marker + substitute(fragment, escaped)


def content_type(headers: dict, payload=None) -> str:
    types = [value for key, value in headers.items() if key.lower() == "content-type"]
    if types:
        return types[-1].partition(";")[0].strip().lower()
    return "application/json" if isinstance(payload, str) and payload.lstrip().startswith(("{", "[")) else "application/x-www-form-urlencoded"


def prepare_headers(headers: dict, mapping: dict, payload=None) -> dict:
    out = {key: (substitute_url(value, mapping) if key.lower() in {"referer", "origin"}
                 and value.startswith(("https://", "http://")) else substitute(value, mapping))
           for key, value in headers.items()}
    if isinstance(payload, str) and not any(key.lower() == "content-type" for key in out):
        out["Content-Type"] = content_type(out, payload)
    return out


def _json_payload(value, mapping: dict, graphql: bool):
    if graphql and isinstance(value, list):
        return [_json_payload(item, mapping, graphql) for item in value]
    if graphql and isinstance(value, dict) and isinstance(value.get("query"), str):
        out = substitute({key: item for key, item in value.items() if key != "query"}, mapping)
        out["query"] = substitute_graphql(value["query"], mapping)
        return out
    return substitute(value, mapping)


def substitute_payload(payload, mapping: dict, headers: dict, *, graphql: bool = False, payload_format: str = "simple"):
    if payload_format == "maigret":
        return _maigret_payload(payload, mapping, graphql)
    if payload_format != "simple":
        raise ValueError("unsupported payload format")
    if not isinstance(payload, str):
        return _json_payload(payload, mapping, graphql)
    media = content_type(headers, payload)
    if media == "application/json" or media.endswith("+json"):
        # Parse before replacing: quotes/backslashes in the identifier cannot
        # become JSON syntax or alter neighbouring fields.
        value = _json_payload(json.loads(payload), mapping, graphql)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if media == "application/x-www-form-urlencoded":
        return substitute(payload, {key: quote_plus(item, safe="") for key, item in mapping.items()})
    return substitute(payload, mapping)
