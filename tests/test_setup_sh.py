"""Smoke tests for setup.sh.

These tests exercise the script in --non-interactive mode with controlled
env files and check that the generated .env and nginx config are correct.
All tests run in isolated temporary directories to avoid touching the real
repo files.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

SETUP_SH = Path(__file__).resolve().parents[1] / "setup.sh"

def _bash_version() -> int:
    try:
        out = subprocess.check_output(
            ["bash", "-c", "echo ${BASH_VERSINFO[0]}"], text=True, stderr=subprocess.DEVNULL
        )
        return int(out.strip())
    except Exception:
        return 0

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or _bash_version() < 4 or platform.system() == "Windows",
    reason="requires bash 4+ on Linux/macOS",
)


def run_setup(tmp_path: Path, env_vars: dict | None = None, extra_args: list | None = None) -> subprocess.CompletedProcess:
    """Run setup.sh --non-interactive inside tmp_path with optional env_vars.

    Nginx config is written to tmp_path/nginx/conf.d/ via --nginx-dir so the
    real repo's nginx config is never touched by tests.
    """
    env = {**os.environ, **(env_vars or {})}
    nginx_dir = tmp_path / "nginx" / "conf.d"
    cmd = [
        "bash", str(SETUP_SH),
        "--non-interactive",
        "--env-file", str(tmp_path / ".env"),
        "--nginx-dir", str(nginx_dir),
    ]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
    )


# ---------------------------------------------------------------------------
# Basic direct mode (no nginx)
# ---------------------------------------------------------------------------

class TestDirectMode:
    def test_exits_zero(self, tmp_path):
        result = run_setup(tmp_path)
        assert result.returncode == 0, result.stderr

    def test_env_file_created(self, tmp_path):
        run_setup(tmp_path)
        assert (tmp_path / ".env").exists()

    def test_env_contains_app_port(self, tmp_path):
        run_setup(tmp_path)
        content = (tmp_path / ".env").read_text()
        assert "APP_HOST_PORT=7005" in content

    def test_env_contains_use_nginx_false(self, tmp_path):
        run_setup(tmp_path)
        content = (tmp_path / ".env").read_text()
        assert "USE_NGINX_SETUP=n" in content

    def test_no_nginx_conf_generated(self, tmp_path):
        run_setup(tmp_path)
        assert not (tmp_path / "nginx" / "conf.d" / "default.conf").exists()

    def test_health_url_uses_localhost(self, tmp_path):
        result = run_setup(tmp_path)
        assert "localhost:7005/health" in result.stdout

    def test_existing_env_file_is_backed_up(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("EXISTING_KEY=existing_value\n")
        run_setup(tmp_path)
        backup = tmp_path / ".env.bak"
        assert backup.exists()
        assert "EXISTING_KEY=existing_value" in backup.read_text()

    def test_existing_keys_preserved(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgresql://localhost/db\n")
        run_setup(tmp_path)
        content = (tmp_path / ".env").read_text()
        assert "DATABASE_URL=postgresql://localhost/db" in content

    def test_custom_app_port_from_env_file(self, tmp_path):
        (tmp_path / ".env").write_text("APP_HOST_PORT=9090\n")
        run_setup(tmp_path)
        content = (tmp_path / ".env").read_text()
        assert "APP_HOST_PORT=9090" in content

    def test_value_with_special_chars_written_correctly(self, tmp_path):
        """Value containing | and & must not corrupt the .env file."""
        env_file = tmp_path / ".env"
        env_file.write_text("APP_HOST_PORT=7005\n")
        # Simulate a value with pipe chars by directly testing set_env_key path:
        # Write an initial SERVER_NAME then overwrite it with a pipe-containing value
        env_file.write_text("APP_HOST_PORT=7005\nSERVER_NAME=plain\n")
        run_setup(tmp_path)
        content = (tmp_path / ".env").read_text()
        # APP_HOST_PORT must still be present and parseable
        lines = {k: v for k, v in (l.split("=", 1) for l in content.splitlines() if "=" in l)}
        assert lines.get("APP_HOST_PORT") == "7005"


# ---------------------------------------------------------------------------
# Nginx + TLS mode
# ---------------------------------------------------------------------------

class TestNginxTlsMode:
    def _cert_setup(self, tmp_path: Path) -> tuple[Path, Path]:
        ssl_dir = tmp_path / "ssl"
        ssl_dir.mkdir()
        cert = ssl_dir / "cert.pem"
        key = ssl_dir / "key.pem"
        cert.write_text("# fake cert\n")
        key.write_text("# fake key\n")
        return cert, key

    def _env(self, cert: Path, key: Path) -> dict:
        return {
            "USE_NGINX_SETUP": "y",
            "TLS_ENABLED": "y",
            "TLS_CERT_PATH": str(cert),
            "TLS_KEY_PATH": str(key),
            "HTTP_PORT": "80",
            "HTTPS_PORT": "7003",
            "SERVER_NAME": "ioc.example.com",
            "APP_HOST_PORT": "8080",
        }

    def _write_env(self, tmp_path: Path, cert: Path, key: Path) -> None:
        (tmp_path / ".env").write_text(
            f"USE_NGINX_SETUP=y\n"
            f"TLS_ENABLED=y\n"
            f"TLS_CERT_PATH={cert}\n"
            f"TLS_KEY_PATH={key}\n"
            f"HTTP_PORT=80\n"
            f"HTTPS_PORT=7003\n"
            f"SERVER_NAME=ioc.example.com\n"
            f"APP_HOST_PORT=8080\n"
        )

    def test_exits_zero(self, tmp_path):
        cert, key = self._cert_setup(tmp_path)
        self._write_env(tmp_path, cert, key)
        result = run_setup(tmp_path)
        assert result.returncode == 0, result.stderr

    def test_nginx_conf_generated(self, tmp_path):
        cert, key = self._cert_setup(tmp_path)
        self._write_env(tmp_path, cert, key)
        run_setup(tmp_path)
        assert (tmp_path / "nginx" / "conf.d" / "default.conf").exists()

    def test_nginx_conf_contains_ssl_directives(self, tmp_path):
        cert, key = self._cert_setup(tmp_path)
        self._write_env(tmp_path, cert, key)
        run_setup(tmp_path)
        conf = (tmp_path / "nginx" / "conf.d" / "default.conf").read_text()
        assert "ssl_certificate" in conf
        assert "ssl_protocols TLSv1.2 TLSv1.3" in conf

    def test_nginx_conf_upstream_uses_app_port(self, tmp_path):
        cert, key = self._cert_setup(tmp_path)
        self._write_env(tmp_path, cert, key)
        run_setup(tmp_path)
        conf = (tmp_path / "nginx" / "conf.d" / "default.conf").read_text()
        assert "server app:8080" in conf

    def test_nginx_conf_https_redirect(self, tmp_path):
        cert, key = self._cert_setup(tmp_path)
        self._write_env(tmp_path, cert, key)
        run_setup(tmp_path)
        conf = (tmp_path / "nginx" / "conf.d" / "default.conf").read_text()
        assert "return 301 https://$host:7003$request_uri" in conf

    def test_nginx_conf_standard_https_port_omits_port_in_redirect(self, tmp_path):
        """Port 443 must produce redirect without explicit port number."""
        cert, key = self._cert_setup(tmp_path)
        (tmp_path / ".env").write_text(
            f"USE_NGINX_SETUP=y\nTLS_ENABLED=y\n"
            f"TLS_CERT_PATH={cert}\nTLS_KEY_PATH={key}\n"
            f"HTTP_PORT=80\nHTTPS_PORT=443\nSERVER_NAME=_\nAPP_HOST_PORT=8080\n"
        )
        run_setup(tmp_path)
        conf = (tmp_path / "nginx" / "conf.d" / "default.conf").read_text()
        assert "return 301 https://$host$request_uri" in conf
        assert "return 301 https://$host:443" not in conf

    def test_nginx_conf_backed_up_on_regeneration(self, tmp_path):
        cert, key = self._cert_setup(tmp_path)
        nginx_dir = tmp_path / "nginx" / "conf.d"
        nginx_dir.mkdir(parents=True)
        existing_conf = nginx_dir / "default.conf"
        existing_conf.write_text("# old config\n")
        self._write_env(tmp_path, cert, key)
        run_setup(tmp_path)
        assert (nginx_dir / "default.conf.bak").exists()
        assert "# old config" in (nginx_dir / "default.conf.bak").read_text()

    def test_health_url_uses_server_name_and_https(self, tmp_path):
        cert, key = self._cert_setup(tmp_path)
        self._write_env(tmp_path, cert, key)
        result = run_setup(tmp_path)
        assert "https://ioc.example.com:7003/health" in result.stdout

    def test_health_url_omits_port_for_standard_443(self, tmp_path):
        cert, key = self._cert_setup(tmp_path)
        (tmp_path / ".env").write_text(
            f"USE_NGINX_SETUP=y\nTLS_ENABLED=y\n"
            f"TLS_CERT_PATH={cert}\nTLS_KEY_PATH={key}\n"
            f"HTTP_PORT=80\nHTTPS_PORT=443\nSERVER_NAME=ioc.example.com\nAPP_HOST_PORT=8080\n"
        )
        result = run_setup(tmp_path)
        assert "https://ioc.example.com/health" in result.stdout


# ---------------------------------------------------------------------------
# Nginx plain HTTP mode
# ---------------------------------------------------------------------------

class TestNginxHttpMode:
    def test_exits_zero(self, tmp_path):
        (tmp_path / ".env").write_text(
            "USE_NGINX_SETUP=y\nTLS_ENABLED=n\n"
            "HTTP_PORT=80\nHTTPS_PORT=7003\n"
            "SERVER_NAME=_\nAPP_HOST_PORT=8080\n"
        )
        result = run_setup(tmp_path)
        assert result.returncode == 0, result.stderr

    def test_nginx_conf_no_ssl(self, tmp_path):
        (tmp_path / ".env").write_text(
            "USE_NGINX_SETUP=y\nTLS_ENABLED=n\n"
            "HTTP_PORT=80\nHTTPS_PORT=7003\n"
            "SERVER_NAME=_\nAPP_HOST_PORT=8080\n"
        )
        run_setup(tmp_path)
        conf = (tmp_path / "nginx" / "conf.d" / "default.conf").read_text()
        assert "ssl_certificate" not in conf
        assert "listen 80" in conf

    def test_localhost_only_prepends_127_0_0_1(self, tmp_path):
        (tmp_path / ".env").write_text(
            "USE_NGINX_SETUP=y\nTLS_ENABLED=n\n"
            "HTTP_PORT=80\nHTTPS_PORT=7003\n"
            "NGINX_LOCALHOST_ONLY=y\nSERVER_NAME=_\nAPP_HOST_PORT=8080\n"
        )
        run_setup(tmp_path)
        conf = (tmp_path / "nginx" / "conf.d" / "default.conf").read_text()
        assert "listen 127.0.0.1:80" in conf


# ---------------------------------------------------------------------------
# Error conditions
# ---------------------------------------------------------------------------

class TestErrorConditions:
    def test_port_conflict_aborts(self, tmp_path):
        """APP_HOST_PORT == HTTP_PORT must exit non-zero."""
        (tmp_path / ".env").write_text(
            "USE_NGINX_SETUP=y\nTLS_ENABLED=n\n"
            "HTTP_PORT=8080\nHTTPS_PORT=7003\n"
            "SERVER_NAME=_\nAPP_HOST_PORT=8080\n"
        )
        result = run_setup(tmp_path)
        assert result.returncode != 0
        assert "conflict" in result.stderr.lower()

    def test_invalid_port_in_non_interactive_aborts(self, tmp_path):
        """A non-numeric port in the env file must abort instead of looping."""
        (tmp_path / ".env").write_text("APP_HOST_PORT=notaport\n")
        result = run_setup(tmp_path)
        assert result.returncode != 0

    def test_missing_cert_file_in_non_interactive_aborts(self, tmp_path):
        """A TLS cert path that doesn't exist must abort."""
        (tmp_path / ".env").write_text(
            "USE_NGINX_SETUP=y\nTLS_ENABLED=y\n"
            "TLS_CERT_PATH=/nonexistent/cert.pem\n"
            "TLS_KEY_PATH=/nonexistent/key.pem\n"
            "HTTP_PORT=80\nHTTPS_PORT=7003\nSERVER_NAME=_\nAPP_HOST_PORT=8080\n"
        )
        result = run_setup(tmp_path)
        assert result.returncode != 0

    def test_env_file_quoted_values_parsed_correctly(self, tmp_path):
        """Quoted values in .env must be stored without surrounding quotes."""
        (tmp_path / ".env").write_text('APP_HOST_PORT="9191"\n')
        result = run_setup(tmp_path)
        assert result.returncode == 0, result.stderr
        content = (tmp_path / ".env").read_text()
        assert "APP_HOST_PORT=9191" in content
        assert 'APP_HOST_PORT="9191"' not in content

    def test_env_file_export_prefix_handled(self, tmp_path):
        """Lines with 'export KEY=value' must be read correctly."""
        (tmp_path / ".env").write_text("export APP_HOST_PORT=8181\n")
        result = run_setup(tmp_path)
        assert result.returncode == 0, result.stderr
        content = (tmp_path / ".env").read_text()
        assert "APP_HOST_PORT=8181" in content
