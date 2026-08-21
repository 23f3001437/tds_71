import copy

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

VALID = {
    "environment": "prod-83m3fz",
    "state": {"backend": "gcs", "locked": True},
    "providerVersion": "~> 6.0",
    "destroyApproved": False,
    "resource": {
        "address": "google_storage_bucket.data",
        "type": "storage_bucket",
        "action": "create",
        "labels": {
            "owner": "student-8kzjj",
            "environment": "production",
            "cost_center": "cc-nbv4",
        },
        "secret": None,
        "forceDestroy": False,
    },
}


def plan(payload):
    r = client.post("/terraform/plan", json=payload)
    assert r.status_code == 200
    return r.json()


def variant(**kw):
    p = copy.deepcopy(VALID)
    for k, v in kw.items():
        if k in ("address", "type", "action", "labels", "secret", "forceDestroy"):
            p["resource"][k] = v
        else:
            p[k] = v
    return p


def test_valid_create():
    assert plan(VALID) == {"decision": "approve", "reason": "APPROVE"}


def test_valid_update():
    assert plan(variant(action="update"))["reason"] == "APPROVE"


def test_approved_delete():
    p = variant(action="delete", destroyApproved=True)
    assert plan(p)["reason"] == "APPROVE"


def test_non_stateful_delete_needs_no_approval():
    p = variant(action="delete", type="compute_address")
    assert plan(p)["reason"] == "APPROVE"


def test_secret_reference_allowed():
    assert plan(variant(secret="secret://projects/x/secrets/db"))["reason"] == "APPROVE"


def test_bad_types_are_invalid_plan():
    assert plan(variant(destroyApproved="no"))["reason"] == "INVALID_PLAN"
    assert plan(variant(state={"backend": "gcs", "locked": "yes"}))["reason"] == "INVALID_PLAN"
    assert plan(variant(action="destroy"))["reason"] == "INVALID_PLAN"
    assert plan(variant(forceDestroy=None))["reason"] == "INVALID_PLAN"
    assert plan("nope")["reason"] == "INVALID_PLAN"


def test_environment_mismatch():
    assert plan(variant(environment="staging-1"))["reason"] == "ENVIRONMENT_MISMATCH"


def test_local_backend_is_state_unsafe():
    p = variant(state={"backend": "local", "locked": True})
    assert plan(p)["reason"] == "STATE_UNSAFE"


def test_unlocked_state_is_unsafe():
    p = variant(state={"backend": "s3", "locked": False})
    assert plan(p)["reason"] == "STATE_UNSAFE"


def test_all_remote_backends_ok():
    for backend in ("gcs", "s3", "azurerm", "remote"):
        p = variant(state={"backend": backend, "locked": True})
        assert plan(p)["reason"] == "APPROVE", backend


def test_unpinned_providers():
    for version in (">= 6.0", "*", "latest", ">= 6.0, < 7.0", ">6.1", ""):
        assert plan(variant(providerVersion=version))["reason"] == "UNPINNED_PROVIDER", version


def test_pinned_providers():
    for version in ("6.2.1", "= 6.2.1", "~> 6.0", "~>6.2"):
        assert plan(variant(providerVersion=version))["reason"] == "APPROVE", version


def test_missing_label():
    labels = dict(VALID["resource"]["labels"])
    labels.pop("cost_center")
    assert plan(variant(labels=labels))["reason"] == "MISSING_LABELS"


def test_wrong_label_value():
    labels = dict(VALID["resource"]["labels"])
    labels["environment"] = "staging"
    assert plan(variant(labels=labels))["reason"] == "MISSING_LABELS"


def test_extra_label_is_fine():
    labels = dict(VALID["resource"]["labels"])
    labels["team"] = "data"
    assert plan(variant(labels=labels))["reason"] == "APPROVE"


def test_plaintext_secret():
    assert plan(variant(secret="hunter2"))["reason"] == "PLAINTEXT_SECRET"


def test_empty_secret_is_plaintext():
    assert plan(variant(secret=""))["reason"] == "PLAINTEXT_SECRET"


def test_bare_scheme_is_plaintext():
    assert plan(variant(secret="secret://"))["reason"] == "PLAINTEXT_SECRET"


def test_delete_not_approved():
    for rtype in ("storage_bucket", "sql_database", "persistent_disk"):
        p = variant(action="delete", type=rtype)
        assert plan(p)["reason"] == "DELETE_NOT_APPROVED", rtype


def test_force_destroy_bucket():
    assert plan(variant(forceDestroy=True))["reason"] == "FORCE_DESTROY"


def test_delete_checked_before_force_destroy():
    p = variant(action="delete", forceDestroy=True)
    assert plan(p)["reason"] == "DELETE_NOT_APPROVED"


def test_force_destroy_on_approved_delete_still_rejected():
    p = variant(action="delete", forceDestroy=True, destroyApproved=True)
    assert plan(p)["reason"] == "FORCE_DESTROY"
