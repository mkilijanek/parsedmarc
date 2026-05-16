"""
export_svc — export job rendering, persistence, and spawning.

All functions are closures bound to the injected dependencies via
make_export_service(). Nothing in this module imports from factory.py.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Thread
from typing import Any, Dict, List

from sqlalchemy import select

from ..formatters import FORMATTERS
from ..models import ExportJob, Indicator


def make_export_service(*, cfg, db_fn, app_log_fn, count_indicators_fn, query_indicators_fn, get_setting_fn, ttl_hours_fn=None):
    """Return a namespace of export-related functions."""

    # ------------------------------------------------------------------ render

    def _render_export_body(fmt: str, rows: List[Indicator]) -> tuple[str, str]:
        func_, mime = FORMATTERS[fmt]
        try:
            if fmt == "elasticsearch":
                body = func_(rows)  # type: ignore[arg-type]
            else:
                body = func_(rows)  # type: ignore[misc]
        except TypeError:
            body = func_(rows)  # type: ignore[misc]
        return body, mime

    # ------------------------------------------------------------------ persist

    def _persist_export_job(job_id: str, fmt: str, params: Dict[str, Any]) -> None:
        db = db_fn()
        try:
            ttl_hours = ttl_hours_fn() if ttl_hours_fn else cfg.EXPORT_JOB_TTL_HOURS
            expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
            db.add(
                ExportJob(
                    job_id=job_id,
                    fmt=fmt,
                    status="queued",
                    query_json=params,
                    access_token=secrets.token_hex(32),
                    expires_at=expires_at,
                )
            )
            db.commit()
        finally:
            db.close()

    # ------------------------------------------------------------------ run

    def _run_export_job(job_id: str) -> None:
        db = db_fn()
        out_dir = Path(cfg.EXPORT_JOB_DIR)
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            job = db.scalar(select(ExportJob).where(ExportJob.job_id == job_id))
            if not job:
                return
            job.status = "running"
            db.commit()
            params = dict(job.query_json or {})
            fmt = str(job.fmt)
            rows = query_indicators_fn(
                db,
                params.get("q"),
                params.get("type_filter"),
                params.get("tlp"),
                params.get("source"),
                int(params.get("min_conf")) if params.get("min_conf") is not None else None,
                int(params.get("max_conf")) if params.get("max_conf") is not None else None,
                limit=int(params.get("limit", 100000)),
                offset=int(params.get("offset", 0)),
            )
            out_path: Path
            if fmt == "sentinel_graph":
                from ..services.sentinel_graph import push_indicators_to_graph

                auth_mode = str(params.get("auth_mode") or get_setting_fn(db, "sentinel.auth_mode", cfg.AZURE_SENTINEL_AUTH_MODE)).strip() or "client_secret"
                result = push_indicators_to_graph(
                    indicators=rows,
                    tenant_id=str(params.get("tenant_id") or get_setting_fn(db, "sentinel.tenant_id", cfg.AZURE_SENTINEL_TENANT_ID)),
                    client_id=str(params.get("client_id") or get_setting_fn(db, "sentinel.client_id", cfg.AZURE_SENTINEL_CLIENT_ID)),
                    scope=str(params.get("scope") or get_setting_fn(db, "sentinel.scope", cfg.AZURE_SENTINEL_SCOPE)),
                    auth_mode=auth_mode,
                    client_secret=str(get_setting_fn(db, "sentinel.client_secret", cfg.AZURE_SENTINEL_CLIENT_SECRET, secret=True)),
                    cert_private_key_pem=str(get_setting_fn(db, "sentinel.cert_private_key_pem", cfg.AZURE_SENTINEL_CERT_PRIVATE_KEY_PEM, secret=True)),
                    cert_thumbprint=str(params.get("cert_thumbprint") or get_setting_fn(db, "sentinel.cert_thumbprint", cfg.AZURE_SENTINEL_CERT_THUMBPRINT)),
                    endpoint_url=str(params.get("endpoint_url") or get_setting_fn(db, "sentinel.endpoint_url", cfg.AZURE_SENTINEL_ENDPOINT_URL)),
                    chunk_size=int(params.get("chunk_size") or get_setting_fn(db, "sentinel.chunk_size", str(cfg.AZURE_SENTINEL_CHUNK_SIZE)) or cfg.AZURE_SENTINEL_CHUNK_SIZE),
                    timeout_s=max(1, int(cfg.FEED_HTTP_TIMEOUT_S)),
                )
                out_path = out_dir / f"{job_id}.json"
                out_path.write_text(json.dumps(result, separators=(",", ":")), encoding="utf-8")
            else:
                body, _ = _render_export_body(fmt, rows)
                out_path = out_dir / f"{job_id}.{fmt}"
                out_path.write_text(body, encoding="utf-8")
            job.status = "completed"
            job.result_path = str(out_path)
            job.error = None
            db.commit()
        except Exception as e:
            try:
                job = db.scalar(select(ExportJob).where(ExportJob.job_id == job_id))
                if job:
                    job.status = "failed"
                    job.error = str(e)
                    db.commit()
            except Exception:
                db.rollback()
        finally:
            db.close()

    # ------------------------------------------------------------------ spawn

    def _spawn_export_job(job_id: str) -> None:
        # app reference is not available here; callers must check TESTING themselves
        # or use the testing-aware wrapper in factory.py (which overrides this).
        th = Thread(target=_run_export_job, args=(job_id,), daemon=True)
        th.start()

    # ------------------------------------------------------------------ namespace

    from types import SimpleNamespace

    return SimpleNamespace(
        render_export_body=_render_export_body,
        persist_export_job=_persist_export_job,
        run_export_job=_run_export_job,
        spawn_export_job=_spawn_export_job,
    )
