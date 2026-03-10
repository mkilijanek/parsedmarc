from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_uses_healthz_for_image_liveness():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "http://localhost:8080/healthz" in dockerfile
    assert "http://localhost:8080/health || exit 1" not in dockerfile


def test_deploy_script_waits_for_readyz():
    script = (ROOT / "scripts" / "deploy-compose.sh").read_text()
    assert "/readyz" in script
    assert 'http://127.0.0.1:${host_port}/health"' not in script


def test_chaos_check_uses_healthz_and_readyz_contracts():
    script = (ROOT / "scripts" / "m15_chaos_check.sh").read_text()
    assert "/healthz" in script
    assert "/readyz" in script
    assert '${BASE_URL}/health"' not in script
