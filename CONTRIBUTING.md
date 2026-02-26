# Contributing

Status: updated for 1.1.x (2026-02-26).

This project uses a strict "green-only" merge policy.

## Local Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional helper (if present):

```bash
source scripts/dev-env.sh
```

## Quality Gate (M6)

Before opening or merging a PR:

1. Run full test suite:
```bash
PYTHONPATH=. pytest -q
```
2. Run focused smoke checks for core API paths:
```bash
PYTHONPATH=. pytest -q \
  tests/test_api.py::TestHealthEndpoint::test_health_success \
  tests/test_api.py::TestIndicatorsViewEndpoint::test_indicators_view_basic \
  tests/test_api.py::TestExportEndpoints::test_export_json_format
```
3. Ensure no unstaged local artifacts are included unintentionally.
4. Ensure docs are updated for behavior/config changes.

## CI Gate (M7)

GitHub Actions workflow `CI` runs on push/PR and currently requires:

- `pytest -q` on Python 3.11
- `pytest -q` on Python 3.12

PRs should be merged only when all checks are green.

## Branching Notes

- Use short-lived feature branches off the active integration branch.
- Keep contributor branches (`kili`, `kili-dev`, `kordek`) periodically synced with `main`.
