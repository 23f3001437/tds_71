"""TDS — Terraform Plan Policy Gate.

Reviews one normalized Terraform resource change before `apply`.
Rules are evaluated in the mandated order; the first failure wins.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Tuple

WORKSPACE = "prod-83m3fz"

REQUIRED_LABELS = {
    "owner": "student-8kzjj",
    "environment": "production",
    "cost_center": "cc-nbv4",
}

REMOTE_BACKENDS = {"gcs", "s3", "azurerm", "remote"}

STATEFUL_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}

VALID_ACTIONS = {"create", "update", "delete"}

# Exact: "6.2.1" or "= 6.2.1"  |  Pessimistic: "~> 6.0"
EXACT_VERSION_RE = re.compile(r"^=?\s*\d+(\.\d+)*$")
PESSIMISTIC_RE = re.compile(r"^~>\s*\d+(\.\d+)*$")

SECRET_REF_RE = re.compile(r"^secret://\S.*$")


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def provider_is_pinned(version: str) -> bool:
    v = version.strip()
    if not v:
        return False
    lowered = v.lower()
    # Pessimistic constraint is checked first: "~>" contains ">".
    if PESSIMISTIC_RE.match(v):
        return True
    # Explicitly unpinned forms.
    if "latest" in lowered or "*" in v or ">" in v or "<" in v:
        return False
    if "," in v:  # ranges like ">= 6.0, < 7.0"
        return False
    return bool(EXACT_VERSION_RE.match(v))


def evaluate_plan(payload: Any) -> Tuple[str, str]:
    # ---- 1. Structural types -------------------------------------------
    if not isinstance(payload, dict):
        return "reject", "INVALID_PLAN"

    environment = payload.get("environment")
    state = payload.get("state")
    provider_version = payload.get("providerVersion")
    destroy_approved = payload.get("destroyApproved")
    resource = payload.get("resource")

    if not _is_str(environment):
        return "reject", "INVALID_PLAN"
    if not isinstance(state, dict):
        return "reject", "INVALID_PLAN"
    if not _is_str(state.get("backend")) or not _is_bool(state.get("locked")):
        return "reject", "INVALID_PLAN"
    if not _is_str(provider_version):
        return "reject", "INVALID_PLAN"
    if not _is_bool(destroy_approved):
        return "reject", "INVALID_PLAN"
    if not isinstance(resource, dict):
        return "reject", "INVALID_PLAN"

    address = resource.get("address")
    rtype = resource.get("type")
    action = resource.get("action")
    labels = resource.get("labels")
    secret = resource.get("secret")
    force_destroy = resource.get("forceDestroy")

    if not _is_str(address) or not _is_str(rtype):
        return "reject", "INVALID_PLAN"
    if action not in VALID_ACTIONS:
        return "reject", "INVALID_PLAN"
    if not isinstance(labels, dict):
        return "reject", "INVALID_PLAN"
    if not all(_is_str(k) and _is_str(v) for k, v in labels.items()):
        return "reject", "INVALID_PLAN"
    if secret is not None and not _is_str(secret):
        return "reject", "INVALID_PLAN"
    if not _is_bool(force_destroy):
        return "reject", "INVALID_PLAN"

    # ---- 2. Workspace ---------------------------------------------------
    if environment != WORKSPACE:
        return "reject", "ENVIRONMENT_MISMATCH"

    # ---- 3. Remote state + locking --------------------------------------
    if state["backend"].strip().lower() not in REMOTE_BACKENDS or state["locked"] is not True:
        return "reject", "STATE_UNSAFE"

    # ---- 4. Provider pinning --------------------------------------------
    if not provider_is_pinned(provider_version):
        return "reject", "UNPINNED_PROVIDER"

    # ---- 5. Cost-ownership labels ---------------------------------------
    for key, expected in REQUIRED_LABELS.items():
        if labels.get(key) != expected:
            return "reject", "MISSING_LABELS"

    # ---- 6. No plaintext secrets ----------------------------------------
    if secret is not None and not SECRET_REF_RE.match(secret.strip()):
        return "reject", "PLAINTEXT_SECRET"

    # ---- 7. Stateful deletes need approval ------------------------------
    if action == "delete" and rtype in STATEFUL_TYPES and destroy_approved is not True:
        return "reject", "DELETE_NOT_APPROVED"

    # ---- 8. Never force-destroy a production bucket ----------------------
    if rtype == "storage_bucket" and force_destroy is True:
        return "reject", "FORCE_DESTROY"

    return "approve", "APPROVE"


def terraform_gate(payload: Any) -> Dict[str, str]:
    decision, reason = evaluate_plan(payload)
    return {"decision": decision, "reason": reason}
