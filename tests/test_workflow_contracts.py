from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_ci_waits_for_healthz():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "http://127.0.0.1:8080/healthz" in workflow
    assert "http://127.0.0.1:8080/health && break" not in workflow


def test_release_workflow_uses_updated_dependabot_actions():
    workflow = (ROOT / ".github" / "workflows" / "release-package.yml").read_text()
    assert "docker/login-action@v4" in workflow
    assert "actions/upload-artifact@v7" in workflow
    assert "docker/login-action@v3" not in workflow
    assert "actions/upload-artifact@v4" not in workflow
