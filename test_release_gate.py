import copy

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

SAFE_PREVIEW = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature/x",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {
                "owner": "docker",
                "name": "build-push-action",
                "ref": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
            },
        ],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "buildkit",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}

SAFE_PRODUCTION = {
    "target": "production",
    "event": "push",
    "ref": "refs/heads/main",
    "workflow": {
        **copy.deepcopy(SAFE_PREVIEW["workflow"]),
        "trigger": "push",
        "environmentApproval": True,
    },
    "image": copy.deepcopy(SAFE_PREVIEW["image"]),
}


def gate(payload):
    response = client.post("/release-gate", json=payload)
    assert response.status_code == 200
    return response.json()


def test_safe_preview_promotes():
    assert gate(SAFE_PREVIEW) == {"decision": "promote", "violations": []}


def test_safe_production_promotes():
    assert gate(SAFE_PRODUCTION) == {"decision": "promote", "violations": []}


def test_extra_scope_is_excess_permission():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["permissions"]["actions"] = "write"
    assert gate(payload)["violations"] == ["EXCESS_PERMISSION"]


def test_elevated_scope_is_excess_permission():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["permissions"]["contents"] = "write"
    assert gate(payload)["violations"] == ["EXCESS_PERMISSION"]


def test_pull_request_target_is_unsafe():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["trigger"] = "pull_request_target"
    assert gate(payload)["violations"] == ["UNSAFE_PR_TRIGGER"]


def test_fail_fast_true_is_tests_incomplete():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["failFast"] = True
    assert gate(payload)["violations"] == ["TESTS_INCOMPLETE"]


def test_matrix_incomplete_is_tests_incomplete():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["matrixComplete"] = False
    assert gate(payload)["violations"] == ["TESTS_INCOMPLETE"]


def test_third_party_tag_is_mutable_action():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["actions"][1]["ref"] = "v5"
    assert gate(payload)["violations"] == ["MUTABLE_ACTION"]


def test_uppercase_sha_is_mutable_action():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["actions"][1]["ref"] = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
    assert gate(payload)["violations"] == ["MUTABLE_ACTION"]


def test_short_sha_is_mutable_action():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["actions"][1]["ref"] = "a1b2c3d"
    assert gate(payload)["violations"] == ["MUTABLE_ACTION"]


def test_actions_owner_tag_is_allowed():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["actions"][0]["ref"] = "v4.1.7"
    assert gate(payload)["violations"] == []


def test_image_hardening_violations():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["image"] = {
        "multiStage": False,
        "runsAsRoot": True,
        "secretMode": "arg",
        "criticalVulnerabilities": 3,
        "digestPinned": False,
    }
    assert set(gate(payload)["violations"]) == {
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    }


def test_secret_mode_copy_leaks_layer():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["image"]["secretMode"] = "copy"
    assert gate(payload)["violations"] == ["SECRET_IN_LAYER"]


def test_secret_mode_none_is_allowed():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["image"]["secretMode"] = "none"
    assert gate(payload)["violations"] == []


def test_production_on_pr_ref_is_invalid():
    payload = copy.deepcopy(SAFE_PRODUCTION)
    payload["event"] = "pull_request"
    payload["ref"] = "refs/heads/develop"
    payload["workflow"]["trigger"] = "pull_request"
    assert set(gate(payload)["violations"]) == {"INVALID_PRODUCTION_REF"}


def test_production_missing_approval():
    payload = copy.deepcopy(SAFE_PRODUCTION)
    payload["workflow"].pop("environmentApproval")
    assert gate(payload)["violations"] == ["APPROVAL_REQUIRED"]


def test_preview_does_not_require_approval():
    payload = copy.deepcopy(SAFE_PREVIEW)
    assert "APPROVAL_REQUIRED" not in gate(payload)["violations"]


def test_multi_failure_payload():
    payload = {
        "target": "production",
        "event": "pull_request",
        "ref": "refs/heads/dev",
        "workflow": {
            "trigger": "pull_request_target",
            "permissions": {
                "contents": "write",
                "packages": "write",
                "id-token": "write",
            },
            "testsPassed": False,
            "matrixComplete": False,
            "failFast": True,
            "actions": [{"owner": "third-party", "name": "scan", "ref": "main"}],
        },
        "image": {
            "multiStage": False,
            "runsAsRoot": True,
            "secretMode": "arg",
            "criticalVulnerabilities": 2,
            "digestPinned": False,
        },
    }
    result = gate(payload)
    assert result["decision"] == "block"
    assert set(result["violations"]) == {
        "EXCESS_PERMISSION",
        "UNSAFE_PR_TRIGGER",
        "TESTS_INCOMPLETE",
        "MUTABLE_ACTION",
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
        "INVALID_PRODUCTION_REF",
        "APPROVAL_REQUIRED",
    }


def test_no_duplicate_codes():
    payload = copy.deepcopy(SAFE_PREVIEW)
    payload["workflow"]["actions"] = [
        {"owner": "a", "name": "x", "ref": "v1"},
        {"owner": "b", "name": "y", "ref": "v2"},
    ]
    violations = gate(payload)["violations"]
    assert violations.count("MUTABLE_ACTION") == 1
