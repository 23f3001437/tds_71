"""TDS — OSINT Corroboration Engine.

Decides whether collected open-source records actually support a claim.
Deterministic: every time reference comes from the request, never the wall clock.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

SUBJECT = "rxh0f6.example"

VALID_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}

SECONDS_PER_DAY = 86400.0


def parse_timestamp(raw: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp. Returns None when unparseable."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def is_valid_source(source: Any) -> bool:
    if not isinstance(source, dict):
        return False
    for key in ("id", "origin", "value", "observedAt"):
        if not isinstance(source.get(key), str):
            return False
    return source.get("type") in VALID_TYPES


def is_fresh(source: Dict[str, Any], as_of: datetime, staleness_days: float) -> bool:
    observed = parse_timestamp(source.get("observedAt"))
    if observed is None:
        return False
    age_days = (as_of - observed).total_seconds() / SECONDS_PER_DAY
    return age_days <= staleness_days


def evaluate_claim(payload: Any) -> Dict[str, Any]:
    invalid = {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}
    unverified = {"verdict": "unverified", "confidence": "low", "corroboratingSources": []}

    # ---- 1. Structural validity -----------------------------------------
    if not isinstance(payload, dict):
        return invalid

    claim = payload.get("claim")
    if not isinstance(claim, dict) or not isinstance(claim.get("value"), str):
        return invalid

    as_of = parse_timestamp(payload.get("asOf"))
    if as_of is None:
        return invalid

    staleness_days = payload.get("stalenessDays")
    if isinstance(staleness_days, bool) or not isinstance(staleness_days, (int, float)):
        return invalid

    sources = payload.get("sources")
    if not isinstance(sources, list):
        return invalid

    claim_value = claim["value"]

    # Ignore malformed sources entirely.
    valid_sources = [s for s in sources if is_valid_source(s)]
    fresh_sources = [s for s in valid_sources if is_fresh(s, as_of, staleness_days)]

    # ---- 2. Contradiction by a fresh authoritative source ----------------
    contradicting = [
        s["id"]
        for s in fresh_sources
        if s.get("authoritative") is True and s["value"] != claim_value
    ]
    if contradicting:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(contradicting),
        }

    # ---- 3. Corroboration: one representative per distinct origin --------
    agreeing = [s for s in fresh_sources if s["value"] == claim_value]

    representatives: Dict[str, Dict[str, Any]] = {}
    for source in agreeing:
        origin = source["origin"]
        current = representatives.get(origin)
        if current is None or source["id"] < current["id"]:
            representatives[origin] = source

    reps = list(representatives.values())
    if len(reps) >= 2:
        types = {s["type"] for s in reps}
        return {
            "verdict": "supported",
            "confidence": "high" if len(types) >= 2 else "medium",
            "corroboratingSources": sorted(s["id"] for s in reps),
        }

    # ---- 4. Everything else ----------------------------------------------
    return unverified


def corroborate(payload: Any) -> Dict[str, Any]:
    try:
        return evaluate_claim(payload)
    except Exception:
        return {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}
