"""Username / e-mail variation generators.

* ``expand_pattern``  - user-scanner's compact pattern syntax (``john[0-9]{0-2}``,
  ``[jJ]ohn[_.]doe``), with native parsing and bounded intermediate storage.
* ``name_permutations`` - Maigret/balestek style permutations of name parts
  joined by ``"", "_", "-", "."`` (MIT).
* ``common_variants`` - quick list of the aliases people typically use
  (``fred`` -> ``fred_``, ``_fred``, ``fred1``, ``fred123``, ``fred.official`` ...).
"""
from __future__ import annotations

import itertools
import re
from collections.abc import Iterable

MAX_DEFAULT = 100


def _charset(pattern: str, pos: int, limit: int) -> tuple[list[str], int]:
    """Read a set as merged code-point intervals, retaining only its needed prefix."""
    atoms = []
    while pos < len(pattern) and pattern[pos] != "]":
        value, escaped = pattern[pos], False
        pos += 1
        if value == "\\":
            if pos == len(pattern):
                raise ValueError("pattern ends with an incomplete escape")
            value, escaped = pattern[pos], True
            pos += 1
        atoms.append((value, escaped))
    if pos == len(pattern):
        raise ValueError('pattern is missing a closing "]"')
    intervals, index = [], 0
    while index < len(atoms):
        first = last = ord(atoms[index][0])
        if (index + 2 < len(atoms) and atoms[index + 1] == ("-", False)
                and atoms[index][0] != "-"):
            last = ord(atoms[index + 2][0])
            if last < first:
                raise ValueError("pattern character range runs backwards")
            index += 2
        intervals.append((first, last))
        index += 1
    merged = []
    for first, last in sorted(intervals):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(last, merged[-1][1]))
        else:
            merged.append((first, last))
    chars = []
    for first, last in merged:
        chars.extend(chr(value) for value in range(first, min(last + 1, first + limit - len(chars))))
        if len(chars) == limit:
            break
    return chars, pos + 1


def _lengths(spec: str) -> list[int]:
    if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:;[0-9]+(?:-[0-9]+)?)*", spec):
        raise ValueError("pattern lengths require integers, ranges or semicolon-separated choices")
    lengths = set()
    for part in spec.split(";"):
        first, separator, last = part.partition("-")
        lo, hi = int(first), int(last) if separator else int(first)
        if hi < lo:
            raise ValueError("pattern length range runs backwards")
        if hi > 256:
            raise ValueError("pattern repetition exceeds the 256-character limit")
        lengths.update(range(lo, hi + 1))
    return sorted(lengths)


def expand_pattern(pattern: str, limit: int = MAX_DEFAULT) -> list[str]:
    """Expand sorted character/length choices, with bounded intermediate storage.

    Supports escaped literals and lengths such as ``[a-z]{0;2-3}``. Both the
    expression and each possible result must fit 4096 characters; repetition
    lengths must not exceed256. Invalid syntax is rejected before any output.
    """
    if type(limit) is not int:
        raise ValueError("pattern output limit must be an integer")
    if limit <= 0:
        return []
    if not isinstance(pattern, str) or len(pattern) > 4096:
        raise ValueError("pattern must be a string of at most 4096 characters")
    parsed, literal = [], []
    pos, maximum_length = 0, 0
    while pos < len(pattern):
        value = pattern[pos]
        pos += 1
        if value == "\\":
            if pos == len(pattern):
                raise ValueError("pattern ends with an incomplete escape")
            literal.append(pattern[pos])
            maximum_length += 1
            pos += 1
        elif value == "]":
            raise ValueError('pattern contains an unmatched "]"')
        elif value == "[":
            if literal:
                parsed.append("".join(literal))
                literal = []
            chars, pos = _charset(pattern, pos, limit)
            lengths = [1]
            if pos < len(pattern) and pattern[pos] == "{":
                end = pattern.find("}", pos + 1)
                if end < 0:
                    raise ValueError('pattern is missing a closing "}"')
                lengths = _lengths(pattern[pos + 1:end])
                pos = end + 1
            parsed.append((chars, lengths))
            maximum_length += max(lengths) if chars else 0
        else:
            literal.append(value)
            maximum_length += 1
        if maximum_length > 4096:
            raise ValueError("expanded pattern exceeds the 4096-character limit")
    if literal:
        parsed.append("".join(literal))
    parts = []
    for block in parsed:
        if isinstance(block, str):
            parts.append([block])
            continue
        chars, lengths = block
        options = []
        for length in lengths:
            options.extend("".join(combo) for combo in itertools.islice(
                itertools.product(chars, repeat=length), limit - len(options)))
            if len(options) == limit:
                break
        if not options:
            return []
        parts.append(options)
    return ["".join(combo) for combo in itertools.islice(itertools.product(*parts), limit)]


def name_permutations(parts: Iterable[str], method: str = "strict", limit: int = MAX_DEFAULT) -> list[str]:
    """Permute name parts (e.g. first, last, year) with the usual separators."""
    elements = list({p.strip().lower(): p.strip() for p in parts if p and p.strip()}.values())
    separators = ["", "_", "-", "."]
    out: list[str] = []
    if limit <= 0:
        return out
    seen = set()
    for i in range(1, len(elements) + 1):
        for subset in itertools.permutations(elements, i):
            candidates = []
            if i == 1:
                if method == "all":
                    candidates = [subset[0], "_" + subset[0], subset[0] + "_"]
                else:
                    candidates = [subset[0]]
            else:
                for sep in separators:
                    perm = sep.join(subset)
                    candidates.append(perm)
                    if sep == "":
                        candidates += ["_" + perm, perm + "_"]
            for candidate in candidates:
                if candidate.lower() not in seen:
                    seen.add(candidate.lower())
                    out.append(candidate)
                    if len(out) >= limit:
                        return out
    return out


def common_variants(username: str, limit: int = 30) -> list[str]:
    if limit <= 0:
        return []
    base = username.strip()
    cands = [
        base, base + "_", "_" + base, base + "1", base + "123", base + "01", base + "007", base + "69",
        base + "official", base + ".official", base + "_official", "real" + base, "the" + base, base + "xx",
        base + "tv", base + "yt", base + "x", "x" + base, base + "2", base + "3", base + "99", base + "2000",
        base.replace(".", "_"), base.replace("_", "."), base.replace("_", ""), base.replace(".", ""),
        base.replace("-", "_"), base.lower(), base.capitalize(),
    ]
    seen = set()
    out = [c for c in cands if c and not (c.lower() in seen or seen.add(c.lower()))]
    return out[:limit]
