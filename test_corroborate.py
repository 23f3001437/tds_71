from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

SUBJECT = "rxh0f6.example"
VALUE = "203.0.113.20"
OTHER = "198.51.100.9"


def src(sid, origin, value=VALUE, stype="dns", observed="2026-07-30T00:00:00Z", auth=False):
    return {
        "id": sid,
        "type": stype,
        "origin": origin,
        "observedAt": observed,
        "value": value,
        "authoritative": auth,
    }


def body(sources, as_of="2026-08-01T00:00:00Z", staleness=365, value=VALUE):
    return {
        "claim": {"subject": SUBJECT, "predicate": "resolves_to", "value": value},
        "asOf": as_of,
        "stalenessDays": staleness,
        "sources": sources,
    }


def call(payload):
    r = client.post("/corroborate", json=payload)
    assert r.status_code == 200
    return r.json()


# --- invalid --------------------------------------------------------------

def test_non_object_body():
    assert call(["x"])["verdict"] == "invalid"


def test_non_string_claim_value():
    p = body([])
    p["claim"]["value"] = 42
    assert call(p) == {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}


def test_missing_as_of():
    p = body([])
    del p["asOf"]
    assert call(p)["verdict"] == "invalid"


def test_unparseable_as_of():
    assert call(body([], as_of="not-a-date"))["verdict"] == "invalid"


def test_staleness_not_a_number():
    assert call(body([], staleness="365"))["verdict"] == "invalid"


def test_sources_not_array():
    p = body([])
    p["sources"] = {"s1": {}}
    assert call(p)["verdict"] == "invalid"


# --- contradicted ---------------------------------------------------------

def test_fresh_authoritative_disagreement():
    s = [src("s2", "reg-a", OTHER, "registry", auth=True), src("s1", "resolver-a")]
    out = call(body(s))
    assert out == {"verdict": "contradicted", "confidence": "low", "corroboratingSources": ["s2"]}


def test_multiple_contradictors_sorted():
    s = [
        src("s9", "reg-b", OTHER, "registry", auth=True),
        src("s3", "reg-a", OTHER, "registry", auth=True),
    ]
    assert call(body(s))["corroboratingSources"] == ["s3", "s9"]


def test_stale_authoritative_disagreement_does_not_contradict():
    s = [
        src("s1", "reg-a", OTHER, "registry", observed="2020-01-01T00:00:00Z", auth=True),
        src("s2", "resolver-a", stype="dns"),
        src("s3", "ct-a", stype="ct_log"),
    ]
    out = call(body(s))
    assert out["verdict"] == "supported"
    assert out["corroboratingSources"] == ["s2", "s3"]


def test_non_authoritative_disagreement_is_ignored():
    s = [src("s1", "resolver-a"), src("s2", "ct-a", OTHER, "ct_log")]
    assert call(body(s))["verdict"] == "unverified"


# --- supported ------------------------------------------------------------

def test_two_types_is_high():
    s = [src("s1", "resolver-a", stype="dns"), src("s2", "ct-a", stype="ct_log")]
    out = call(body(s))
    assert out == {
        "verdict": "supported",
        "confidence": "high",
        "corroboratingSources": ["s1", "s2"],
    }


def test_single_type_is_medium():
    s = [src("s1", "resolver-a"), src("s2", "resolver-b")]
    assert call(body(s))["confidence"] == "medium"


def test_mirrors_reduce_to_smallest_id():
    s = [
        src("s5", "resolver-a"),
        src("s2", "resolver-a"),
        src("s7", "resolver-b", stype="scan"),
    ]
    out = call(body(s))
    assert out["verdict"] == "supported"
    assert out["corroboratingSources"] == ["s2", "s7"]


def test_lexicographic_not_numeric_id_ordering():
    s = [src("s10", "resolver-a"), src("s9", "resolver-a"), src("s1", "resolver-b")]
    out = call(body(s))
    # "s10" < "s9" lexicographically, so s10 represents resolver-a.
    assert out["corroboratingSources"] == ["s1", "s10"]


def test_authoritative_agreement_counts_normally():
    s = [src("s1", "reg-a", stype="registry", auth=True), src("s2", "resolver-a")]
    assert call(body(s))["verdict"] == "supported"


# --- unverified -----------------------------------------------------------

def test_no_sources():
    assert call(body([])) == {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": [],
    }


def test_single_source_is_a_lead_only():
    assert call(body([src("s1", "resolver-a")]))["verdict"] == "unverified"


def test_only_mirrors_of_one_origin():
    s = [src("s1", "resolver-a"), src("s2", "resolver-a"), src("s3", "resolver-a")]
    assert call(body(s))["verdict"] == "unverified"


def test_all_agreement_stale():
    s = [
        src("s1", "resolver-a", observed="2020-01-01T00:00:00Z"),
        src("s2", "ct-a", stype="ct_log", observed="2020-01-01T00:00:00Z"),
    ]
    assert call(body(s))["verdict"] == "unverified"


# --- freshness boundary ---------------------------------------------------

def test_exactly_at_window_is_fresh():
    s = [
        src("s1", "resolver-a", observed="2026-07-31T00:00:00Z"),
        src("s2", "ct-a", stype="ct_log", observed="2026-07-31T00:00:00Z"),
    ]
    assert call(body(s, staleness=1))["verdict"] == "supported"


def test_just_past_window_is_stale():
    s = [
        src("s1", "resolver-a", observed="2026-07-30T23:59:59Z"),
        src("s2", "ct-a", stype="ct_log", observed="2026-07-30T23:59:59Z"),
    ]
    assert call(body(s, staleness=1))["verdict"] == "unverified"


def test_offset_timestamps_parse():
    s = [
        src("s1", "resolver-a", observed="2026-07-30T05:30:00+05:30"),
        src("s2", "ct-a", stype="ct_log", observed="2026-07-30T00:00:00Z"),
    ]
    assert call(body(s))["verdict"] == "supported"


# --- source validity ------------------------------------------------------

def test_bad_type_source_ignored():
    s = [src("s1", "resolver-a"), src("s2", "ct-a", stype="whois")]
    assert call(body(s))["verdict"] == "unverified"


def test_missing_field_source_ignored():
    bad = src("s2", "ct-a", stype="ct_log")
    del bad["value"]
    assert call(body([src("s1", "resolver-a"), bad]))["verdict"] == "unverified"


def test_invalid_authoritative_contradictor_ignored():
    bad = src("s2", "reg-a", OTHER, "bogus", auth=True)
    s = [src("s1", "resolver-a"), src("s3", "ct-a", stype="ct_log"), bad]
    assert call(body(s))["verdict"] == "supported"


def test_unparseable_observed_at_is_stale():
    s = [src("s1", "resolver-a", observed="soon"), src("s2", "ct-a", stype="ct_log")]
    assert call(body(s))["verdict"] == "unverified"
