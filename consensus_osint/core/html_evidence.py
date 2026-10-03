"""Preserve original markup while excluding uninstantiated HTML evidence."""
import html
import re
import unicodedata
from html.parser import HTMLParser

_COMMENT_END = re.compile(r"--!?>")
_COMMENT_ABRUPT_END = re.compile(r"-?>")
_JSON_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")


def mentions_query(text: str, query: str) -> bool:
    """Whether a response names the query, including its escaped spellings.

    JSON APIs commonly send non-ASCII names as backslash-u escapes and pages send
    character references; a raw substring test would call those responses
    unrelated to the name they were asked about.
    """
    needle = (query or "").strip().lower()
    haystack = (text or "").lower()
    if needle in haystack:
        return True
    if "\\" not in haystack and "&" not in haystack and needle.isascii():
        return False
    decoded = _JSON_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), text or "").replace("\\/", "/")
    try:  # join surrogate pairs used for characters outside the basic plane
        decoded = decoded.encode("utf-16", "surrogatepass").decode("utf-16")
    except UnicodeError:
        pass
    decoded = unicodedata.normalize("NFC", html.unescape(decoded)).lower()
    return unicodedata.normalize("NFC", needle) in decoded


def mask_comments(text: str) -> str:
    if "<!--" not in text:
        return text
    offsets = [0]
    offsets.extend(match.end() for match in re.finditer("\n", text))
    spans = []

    class Comments(HTMLParser):
        def parse_comment(self, i, report=True):
            # Python patch releases differ on abrupt/malformed closes and on
            # whether EOF comments call handle_comment. Consume each comment
            # here so its boundary is stable and spans cannot overlap. The
            # parser still protects quoted attributes and script/style data.
            close = (_COMMENT_ABRUPT_END.match(self.rawdata, i + 4)
                     or _COMMENT_END.search(self.rawdata, i + 4))
            end = close.end() if close else len(self.rawdata)
            line, column = self.getpos()
            start = offsets[line - 1] + column
            spans.append((start, start + end - i))
            return end

    parser = Comments(convert_charrefs=False)
    parser.feed(text)
    parser.close()
    pieces = []
    previous = 0
    for start, end in spans:
        pieces.extend((text[previous:start], " " * (end - start)))
        previous = end
    pieces.append(text[previous:])
    return "".join(pieces)


def mask_inert(text: str) -> str:
    """Mask comments and template fragments without reserializing live markup."""
    return mask_elements(mask_comments(text), ("template",))


def mask_elements(text: str, names: tuple[str, ...]) -> str:
    """Mask the named elements and their contents, keeping every other offset."""
    lowered = text.lower()
    if not any("<" + name in lowered for name in names):
        return text
    offsets = [0]
    offsets.extend(match.end() for match in re.finditer("\n", text))
    spans = []

    class Templates(HTMLParser):
        depth = 0
        start = 0
        name = None

        def position(self):
            line, column = self.getpos()
            return offsets[line - 1] + column

        def handle_starttag(self, tag, attrs):
            if tag == self.name if self.depth else tag in names:
                if self.depth == 0:
                    self.start = self.position()
                    self.name = tag
                self.depth += 1

        def handle_startendtag(self, tag, attrs):
            # A slash does not close a non-void HTML template element.
            self.handle_starttag(tag, attrs)

        def handle_endtag(self, tag):
            if tag == self.name and self.depth:
                self.depth -= 1
                if not self.depth:
                    end = text.find(">", self.position())
                    spans.append((self.start, end + 1 if end >= 0 else len(text)))

    parser = Templates(convert_charrefs=False)
    parser.feed(text)
    parser.close()
    if parser.depth:
        spans.append((parser.start, len(text)))
    pieces = []
    previous = 0
    for start, end in spans:
        pieces.extend((text[previous:start], " " * (end - start)))
        previous = end
    pieces.append(text[previous:])
    return "".join(pieces)
