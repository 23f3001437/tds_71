"""TDS — LLM Output Handling Gate (OWASP LLM05).

Model output is untrusted input. This gate decides deterministically whether
an output string is safe to hand to a given sink. No LLM, no phrase lists —
structure, schemes, and an exact-hostname allowlist only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

ALLOWED_HOSTS = {"cdn-e1njrey.example", "app-d0mbc0e.example"}

CHANNELS = {"html", "markdown", "url", "sql", "shell"}

MAX_LEN = 20000

# --- structural patterns ---------------------------------------------------

SCRIPT_TAG_RE = re.compile(r"<\s*(script|iframe|object|embed)\b", re.IGNORECASE)
EVENT_HANDLER_RE = re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)
DANGEROUS_SCHEME_RE = re.compile(r"(javascript|data|vbscript)\s*:", re.IGNORECASE)

# html: values of quoted src= / href= attributes
HTML_URL_RE = re.compile(
    r"""\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE
)
# markdown: target inside ](...)
MD_URL_RE = re.compile(r"\]\(\s*([^)\s]+)")

SQL_UNION_RE = re.compile(r"\bunion\b", re.IGNORECASE)
SQL_OR_1_1_RE = re.compile(r"\bor\s+1\s*=\s*1", re.IGNORECASE)

SHELL_CHARS = set(";&|`<>")

NAMED_ENTITIES = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}

NUMERIC_ENTITY_RE = re.compile(r"&#(x[0-9a-fA-F]+|[0-9]+);")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


# --- decoding --------------------------------------------------------------

def decode_once(text: str) -> str:
    """Percent-escapes, then HTML entities, then \\uXXXX escapes. One pass."""
    decoded = unquote(text)

    def _numeric(match: re.Match) -> str:
        token = match.group(1)
        try:
            code = int(token[1:], 16) if token[0] in "xX" else int(token, 10)
            return chr(code)
        except (ValueError, OverflowError):
            return match.group(0)

    decoded = NUMERIC_ENTITY_RE.sub(_numeric, decoded)
    for entity, char in NAMED_ENTITIES.items():
        decoded = decoded.replace(entity, char)
        decoded = decoded.replace(entity.upper(), char)

    def _unicode(match: re.Match) -> str:
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    return UNICODE_ESCAPE_RE.sub(_unicode, decoded)


# --- URL handling ----------------------------------------------------------

def extract_urls(channel: str, text: str) -> List[str]:
    if channel == "html":
        return [q or a for q, a in HTML_URL_RE.findall(text)]
    if channel == "markdown":
        return MD_URL_RE.findall(text)
    if channel == "url":
        stripped = text.strip()
        return [stripped] if stripped else []
    return []


def parsed_host(raw: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Return (is_absolute, scheme, hostname) for a reference."""
    candidate = raw.strip()
    if not candidate:
        return False, None, None

    # Protocol-relative //host/path — a browser fetches it, so treat as absolute.
    if candidate.startswith("//"):
        parsed = urlparse("https:" + candidate)
        return True, "https", (parsed.hostname or "").lower() or None

    parsed = urlparse(candidate)
    if parsed.scheme:
        return True, parsed.scheme.lower(), (parsed.hostname or "").lower() or None

    # Relative reference such as /local/page or images/x.png
    return False, None, None


def url_violation(channel: str, text: str) -> Optional[str]:
    """DANGEROUS_SCHEME then EXTERNAL_EXFIL for URL-bearing channels."""
    if DANGEROUS_SCHEME_RE.search(text):
        return "DANGEROUS_SCHEME"

    urls = extract_urls(channel, text)

    for raw in urls:
        is_absolute, scheme, _ = parsed_host(raw)
        if is_absolute and scheme not in ("http", "https"):
            return "DANGEROUS_SCHEME"

    for raw in urls:
        is_absolute, _, host = parsed_host(raw)
        if not is_absolute:
            continue
        # Hostname only: credentials and query strings never grant access.
        if host not in ALLOWED_HOSTS:
            return "EXTERNAL_EXFIL"

    return None


# --- channel rules ---------------------------------------------------------

def sql_violation(text: str) -> Optional[str]:
    if (
        "'" in text
        or '"' in text
        or ";" in text
        or "--" in text
        or "/*" in text
        or SQL_UNION_RE.search(text)
        or SQL_OR_1_1_RE.search(text)
    ):
        return "SQL_METACHAR"
    return None


def shell_violation(text: str) -> Optional[str]:
    if any(char in SHELL_CHARS for char in text):
        return "SHELL_METACHAR"
    if "$(" in text or "${" in text:
        return "SHELL_METACHAR"
    return None


def channel_violation(channel: str, text: str) -> Optional[str]:
    if channel == "html":
        if SCRIPT_TAG_RE.search(text):
            return "SCRIPT_TAG"
        if EVENT_HANDLER_RE.search(text):
            return "EVENT_HANDLER"
        return url_violation("html", text)
    if channel in ("markdown", "url"):
        return url_violation(channel, text)
    if channel == "sql":
        return sql_violation(text)
    return shell_violation(text)


# --- entry point -----------------------------------------------------------

def evaluate_output(payload: Any) -> Tuple[bool, str]:
    # 1. Schema
    if not isinstance(payload, dict):
        return False, "INVALID_SCHEMA"
    channel = payload.get("channel")
    output = payload.get("output")
    if channel not in CHANNELS:
        return False, "INVALID_SCHEMA"
    if not isinstance(output, str) or len(output) > MAX_LEN:
        return False, "INVALID_SCHEMA"

    # 2. Encoded payload — decode once; if it changed and now trips a rule.
    decoded = decode_once(output)
    if decoded != output and channel_violation(channel, decoded) is not None:
        return False, "ENCODED_PAYLOAD"

    # 3. Channel rules against the original output, first match wins.
    violation = channel_violation(channel, output)
    if violation is not None:
        return False, violation

    return True, "SAFE"


def sanitize_output(payload: Any) -> Dict[str, Any]:
    safe, reason = evaluate_output(payload)
    return {"safe": safe, "reason": reason}
