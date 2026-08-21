# TDS GA7 — CI/CD Container Release Gate

Deterministic policy service that decides whether a GitHub Actions run may promote a container image.

## Endpoint

`POST /release-gate` → `{"decision": "promote" | "block", "violations": ["CODE", ...]}`

`promote` is returned only when `violations` is empty.

## Rules implemented

| Code | Condition |
| --- | --- |
| `EXCESS_PERMISSION` | `permissions` is not exactly `{contents: read, packages: write, id-token: none}` (missing key, elevated value, or any extra scope) |
| `UNSAFE_PR_TRIGGER` | trigger is `pull_request_target`, or `event == pull_request` with a trigger other than `pull_request` |
| `TESTS_INCOMPLETE` | `testsPassed` false, `matrixComplete` false, or `failFast` true |
| `MUTABLE_ACTION` | any action not owned by `actions` whose ref is not `^[0-9a-f]{40}$` |
| `SINGLE_STAGE_IMAGE` | `multiStage` false |
| `ROOT_RUNTIME` | `runsAsRoot` true |
| `SECRET_IN_LAYER` | `secretMode` not in `{none, buildkit}` (i.e. `arg` or `copy`) |
| `CRITICAL_CVE` | `criticalVulnerabilities > 0` |
| `UNPINNED_IMAGE` | `digestPinned` false |
| `INVALID_PRODUCTION_REF` | target `production` without `event == push` on `refs/heads/main` |
| `APPROVAL_REQUIRED` | target `production` without `workflow.environmentApproval == true` |

Codes are de-duplicated; a malformed or empty body blocks rather than 4xx-ing.

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
pytest -q
```

## Deploy (Render)

- Runtime: Python 3.11.9 (pinned in `runtime.txt`)
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

## GitHub Actions evidence

`.github/workflows/release-gate.yml` — workflow name `TDS GA7 Release Gate`, runs on push to `main`,
first step named `TDS identity: 23f3001437@ds.study.iitm.ac.in`, runs the pytest suite across a
`fail-fast: false` matrix and smoke-tests the live endpoint.

Submit the **workflow page** URL:
`https://github.com/<user>/<repo>/actions/workflows/release-gate.yml`
