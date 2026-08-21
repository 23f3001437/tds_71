"""TDS — LLM Action Firewall.

Deterministic post-generation, pre-execution check on a proposed tool call.
No LLM, no suspicious-phrase matching: schemas, scopes, approval, and
structural HTML safety are the entire boundary.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Tuple

TENANT_ID = "tenant-pjxu57c"
EMAIL_DOMAIN = "notify-gxxh70m.example"

ALLOWED_TOOLS = {"search", "lookup_record", "send_email", "render_html"}

# Exact argument key sets — no missing keys, no extra keys.
TOOL_ARG_KEYS = {
    "search": {"query"},
    "lookup_record": {"tenantId", "recordId"},
    "send_email": {"to", "subject", "body"},
    "render_html": {"html"},
}

# Structural HTML hazards.
SCRIPT_RE = re.compile(r"<\s*script\b", re.IGNORECASE)
IFRAME_RE = re.compile(r"<\s*iframe\b", re.IGNORECASE)
CLOSING_SCRIPT_RE = re.compile(r"<\s*/\s*script\b", re.IGNORECASE)
CLOSING_IFRAME_RE = re.compile(r"<\s*/\s*iframe\b", re.IGNORECASE)
# Inline event handlers: on<name> immediately followed by '=' (allowing spaces).
EVENT_HANDLER_RE = re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)
# javascript: URL scheme, tolerating whitespace/newlines inside the scheme.
JS_URL_RE = re.compile(r"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:", re.IGNORECASE)

EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+)$")


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def html_is_unsafe(html: str) -> bool:
    return bool(
        SCRIPT_RE.search(html)
        or CLOSING_SCRIPT_RE.search(html)
        or IFRAME_RE.search(html)
        or CLOSING_IFRAME_RE.search(html)
        or EVENT_HANDLER_RE.search(html)
        or JS_URL_RE.search(html)
    )


def evaluate_action(payload: Any) -> Tuple[str, str]:
    """Return (decision, reason). Checks run in the mandated order."""

    # ---- 1. Top-level schema -------------------------------------------
    if not isinstance(payload, dict):
        return "block", "INVALID_SCHEMA"

    provenance = payload.get("provenance")
    if provenance not in ("trusted", "untrusted"):
        return "block", "INVALID_SCHEMA"

    human_approved = payload.get("humanApproved", False)
    if not isinstance(human_approved, bool):
        return "block", "INVALID_SCHEMA"

    if "untrustedContent" in payload and payload["untrustedContent"] is not None:
        if not _is_str(payload["untrustedContent"]):
            return "block", "INVALID_SCHEMA"

    action = payload.get("action")
    if not isinstance(action, dict):
        return "block", "INVALID_SCHEMA"

    tool = action.get("tool")
    args = action.get("args")
    if not _is_str(tool) or not isinstance(args, dict):
        return "block", "INVALID_SCHEMA"

    # ---- 2. Tool allowlist ---------------------------------------------
    if tool not in ALLOWED_TOOLS:
        return "block", "TOOL_NOT_ALLOWED"

    # ---- 3. Selected tool's argument schema (exact key set) ------------
    if set(args.keys()) != TOOL_ARG_KEYS[tool]:
        return "block", "INVALID_SCHEMA"

    if tool == "search":
        query = args["query"]
        if not _is_str(query) or not (1 <= len(query) <= 200):
            return "block", "INVALID_SCHEMA"
        return "allow", "ALLOW"

    if tool == "lookup_record":
        tenant_id = args["tenantId"]
        record_id = args["recordId"]
        if not _nonempty_str(tenant_id) or not _nonempty_str(record_id):
            return "block", "INVALID_SCHEMA"
        # ---- 4. Tenant scope -------------------------------------------
        if tenant_id != TENANT_ID:
            return "block", "TENANT_SCOPE"
        return "allow", "ALLOW"

    if tool == "send_email":
        to = args["to"]
        subject = args["subject"]
        body = args["body"]
        if not _nonempty_str(to) or not _is_str(subject) or not _is_str(body):
            return "block", "INVALID_SCHEMA"
        match = EMAIL_RE.match(to.strip())
        if not match:
            return "block", "INVALID_SCHEMA"
        # ---- 5. Exact recipient domain ---------------------------------
        if match.group(1).lower() != EMAIL_DOMAIN:
            return "block", "EGRESS_DENIED"
        # ---- 6. Human approval -----------------------------------------
        if human_approved is not True:
            return "block", "APPROVAL_REQUIRED"
        return "allow", "ALLOW"

    # tool == "render_html"
    html = args["html"]
    if not _is_str(html):
        return "block", "INVALID_SCHEMA"
    # ---- 7. Safe rendering ---------------------------------------------
    if html_is_unsafe(html):
        return "block", "UNSAFE_OUTPUT"
    return "allow", "ALLOW"


def firewall(payload: Any) -> Dict[str, str]:
    decision, reason = evaluate_action(payload)
    return {"decision": decision, "reason": reason}
