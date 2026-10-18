"""Compile suffix rules into the GPU program's pattern language."""

import re
import string

HEX = "0123456789ABCDEF"
VARIABLES = "GHIJKLMNOPQRSTUVWXYZ"
MAX_PATTERNS = 256


def expand_pattern(pattern: str) -> str:
    """Validate and expand one pattern without nested groups (maximum 40 digits)."""
    if not pattern.isascii():
        raise ValueError("Patterns must use ASCII characters")
    pattern = pattern.upper()
    if not pattern or len(pattern) > 512:
        raise ValueError("A pattern must contain 1–40 fingerprint digits")
    result = ""
    pos = 0
    while pos < len(pattern):
        if pattern[pos] == "(":
            end = pattern.find(")", pos + 1)
            if end == -1:
                raise ValueError("Unclosed pattern group")
            atom = pattern[pos + 1:end]
            pos = end + 1
        else:
            atom = pattern[pos]
            pos += 1
        if not atom or any(c not in string.ascii_uppercase + string.digits for c in atom):
            raise ValueError("Patterns accept ASCII letters/digits and non-nested groups only")
        count = 1
        if pos < len(pattern) and pattern[pos] == "{":
            end = pattern.find("}", pos + 1)
            if end == -1 or not re.fullmatch(r"[0-9]{1,2}", pattern[pos + 1:end]):
                raise ValueError("Repetition must be an integer from 1 to 40")
            count = int(pattern[pos + 1:end])
            pos = end + 1
            if not 1 <= count <= 40:
                raise ValueError("Repetition must be an integer from 1 to 40")
        if len(result) + len(atom) * count > 40:
            raise ValueError("Expanded patterns cannot exceed the 40-digit fingerprint")
        result += atom * count
    return result


def compile_rules(rules: list[str], patterns: list[str]) -> list[str]:
    """All rules are OR'ed. Different variable letters need not differ in value."""
    candidates = []
    for rule in rules:
        kind, separator, value = rule.partition(":")
        if not separator:
            raise ValueError("Rules use TYPE:VALUE, e.g. suffix:DEADBEEF or repeat:8")
        if kind == "suffix":
            if not re.fullmatch(r"[0-9a-fA-F]{1,40}", value):
                raise ValueError("A suffix must contain 1–40 hexadecimal digits")
            candidates.append(value)
            continue
        if not re.fullmatch(r"[0-9]{1,2}", value):
            raise ValueError("Rule length/count must be an integer")
        count = int(value)
        if kind == "repeat" and 2 <= count <= 40:
            candidates.append("X" * count)
        elif kind == "pair" and 2 <= count <= 20:
            candidates.append("XY" * count)
        elif kind == "palindrome" and 2 <= count <= 40:
            half = VARIABLES[:count // 2]
            middle = VARIABLES[count // 2] if count % 2 else ""
            candidates.append(half + middle + half[::-1])
        elif kind == "sequence" and 2 <= count <= 16:
            for alphabet in (HEX, HEX[::-1]):
                candidates.extend(alphabet[i:i + count] for i in range(17 - count))
        else:
            raise ValueError("Unknown rule or invalid range: repeat 2–40, pair 2–20, "
                             "palindrome 2–40, sequence 2–16")
    for pattern in patterns:
        candidates.extend(pattern.split("|"))
    if not candidates or len(candidates) > MAX_PATTERNS:
        raise ValueError(f"Provide between 1 and {MAX_PATTERNS} patterns")
    return list(dict.fromkeys(expand_pattern(pattern) for pattern in candidates))


def matches(fingerprint: str, pattern: str) -> bool:
    """Independently check the returned fingerprint against an expanded rule."""
    if not re.fullmatch(r"[0-9A-Fa-f]{40}", fingerprint):
        return False
    variables = {}
    for symbol, digit in zip(pattern, fingerprint.upper()[-len(pattern):]):
        if symbol in HEX:
            if digit != symbol:
                return False
        elif variables.setdefault(symbol, digit) != digit:
            return False
    return True
