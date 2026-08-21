"""TDS GA7 — CI/CD Container Release Gate.

Deterministic policy endpoint: POST /release-gate
Returns {"decision": "promote|block", "violations": [...]}
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from firewall import firewall
from terraform_gate import terraform_gate
from sanitize import sanitize_output

SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Exactly least privilege for a release.
REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

SAFE_SECRET_MODES = {"none", "buildkit"}

app = FastAPI(title="TDS GA7 Release Gate", version="1.0.0")


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _norm(value: Any) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


def _is_true(value: Any) -> bool:
    """Tolerate booleans and stringly-typed booleans."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _is_false(value: Any) -> bool:
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return value.strip().lower() == "false"
    return False


def check_permissions(perms: Any) -> bool:
    """True when permissions are EXACTLY the least-privilege release set."""
    if not isinstance(perms, dict):
        return False
    normalized = {_norm(k): _norm(v) for k, v in perms.items()}
    return normalized == REQUIRED_PERMISSIONS


def evaluate(payload: Dict[str, Any]) -> List[str]:
    violations: List[str] = []

    target = _norm(payload.get("target"))
    event = _norm(payload.get("event"))
    ref = payload.get("ref") if isinstance(payload.get("ref"), str) else ""
    workflow = _as_dict(payload.get("workflow"))
    image = _as_dict(payload.get("image"))

    trigger = _norm(workflow.get("trigger"))

    # 1. Least-privilege permissions, exactly.
    if not check_permissions(workflow.get("permissions")):
        violations.append("EXCESS_PERMISSION")

    # 2. Pull requests must use `pull_request`, never `pull_request_target`.
    if trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")
    elif event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests pass, full matrix, fail-fast disabled.
    if (
        not _is_true(workflow.get("testsPassed"))
        or not _is_true(workflow.get("matrixComplete"))
        or not _is_false(workflow.get("failFast"))
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Third-party actions pinned to a full 40-char lowercase SHA.
    actions = workflow.get("actions")
    if isinstance(actions, list):
        for action in actions:
            action = _as_dict(action)
            owner = _norm(action.get("owner"))
            ref_value = action.get("ref")
            ref_value = ref_value.strip() if isinstance(ref_value, str) else ""
            if owner == "actions":
                continue
            if not SHA_RE.match(ref_value):
                violations.append("MUTABLE_ACTION")
                break

    # 5. Hardened image.
    if not _is_true(image.get("multiStage")):
        violations.append("SINGLE_STAGE_IMAGE")
    if _is_true(image.get("runsAsRoot")):
        violations.append("ROOT_RUNTIME")
    if _norm(image.get("secretMode")) not in SAFE_SECRET_MODES:
        violations.append("SECRET_IN_LAYER")
    try:
        cves = int(image.get("criticalVulnerabilities") or 0)
    except (TypeError, ValueError):
        cves = 1
    if cves > 0:
        violations.append("CRITICAL_CVE")
    if not _is_true(image.get("digestPinned")):
        violations.append("UNPINNED_IMAGE")

    # 6. Production-only gates.
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if not _is_true(workflow.get("environmentApproval")):
            violations.append("APPROVAL_REQUIRED")

    # Stable, de-duplicated output.
    seen: set[str] = set()
    ordered: List[str] = []
    for code in violations:
        if code not in seen:
            seen.add(code)
            ordered.append(code)
    return ordered


@app.post("/release-gate")
async def release_gate(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    violations = evaluate(payload)
    return JSONResponse(
        {
            "decision": "promote" if not violations else "block",
            "violations": violations,
        }
    )


@app.post("/action-firewall")
async def action_firewall(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        payload = None
    return JSONResponse(firewall(payload))


@app.post("/terraform/plan")
async def terraform_plan(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        payload = None
    return JSONResponse(terraform_gate(payload))


@app.post("/sanitize-output")
async def sanitize_output_endpoint(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        payload = None
    return JSONResponse(sanitize_output(payload))


@app.get("/")
async def root() -> Dict[str, Any]:
    return {
        "service": "TDS services",
        "endpoints": [
            "POST /release-gate",
            "POST /action-firewall",
            "POST /terraform/plan",
            "POST /sanitize-output",
        ],
    }


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


# CORS registered last so it is the OUTERMOST middleware layer.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
