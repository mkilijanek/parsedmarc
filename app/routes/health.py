from __future__ import annotations

import json
import sys
from typing import Any, Callable

from flask import Blueprint, Response
from sqlalchemy import func, select

from ..cache import get_redis
from ..metrics import cache_access_total
from ..services.common import _dep_status


def _get_redis_runtime():
    # Keep compatibility with tests patching app.main.get_redis.
    main_mod = sys.modules.get("app.main")
    if main_mod is not None and hasattr(main_mod, "get_redis"):
        return getattr(main_mod, "get_redis")()
    return get_redis()


def register_health_blueprint(
    app,
    *,
    limiter,
    cfg,
    db_factory: Callable[..., Any],
    cache_key_fn: Callable[..., str],
) -> None:
    bp = Blueprint("health", __name__)

    @bp.get("/healthz")
    @limiter.limit("120 per minute")
    def healthz():
        return Response(
            json.dumps({"status": "ok"}, separators=(",", ":")),
            status=200,
            mimetype="application/json",
        )

    @bp.get("/health")
    @limiter.limit("60 per minute")
    def health():
        health_cache_key = cache_key_fn("health", deep=True)
        try:
            r = _get_redis_runtime()
            cached = r.get(health_cache_key)
            if isinstance(cached, (str, bytes, bytearray)) and len(cached) > 0:
                cache_access_total.labels(endpoint="health", status="hit").inc()
                return Response(cached, mimetype="application/json")
            cache_access_total.labels(endpoint="health", status="miss").inc()
        except Exception:
            cache_access_total.labels(endpoint="health", status="error").inc()
            r = None

        checks: dict[str, bool] = {"database": False, "redis": False}
        try:
            db = db_factory(read_only=True)
            db.execute(select(func.now()))
            checks["database"] = True
        except Exception:
            checks["database"] = False
        finally:
            try:
                db.close()
            except Exception:
                pass
        try:
            r2 = _get_redis_runtime()
            r2.ping()
            checks["redis"] = True
        except Exception:
            checks["redis"] = False

        dep_all = _dep_status.get_all()
        if cfg.MISP_URL and cfg.MISP_API_KEY:
            misp_entry = dep_all.get("misp") or {}
            checks["misp"] = misp_entry.get("status") == "ok"
        else:
            checks["misp"] = False
        checks["crowdsec"] = bool(cfg.CROWDSEC_API_KEY)

        infra_ok = checks["database"] and checks["redis"]
        status = "healthy" if infra_ok else "degraded"
        payload = {"status": status, "checks": checks}
        body = json.dumps(payload, separators=(",", ":"))
        if r is not None:
            try:
                r.setex(health_cache_key, max(1, cfg.HEALTH_CACHE_TTL), body)
            except Exception:
                cache_access_total.labels(endpoint="health", status="error").inc()
        return Response(body, mimetype="application/json")

    @bp.get("/deps")
    @limiter.limit("30 per minute")
    def deps():
        payload = _dep_status.get_all()
        return Response(json.dumps(payload, separators=(",", ":")), status=200, mimetype="application/json")

    @bp.get("/readyz")
    @limiter.limit("120 per minute")
    def readyz():
        checks = {"database": False, "redis": False}
        try:
            db = db_factory(read_only=True)
            db.execute(select(func.now()))
            checks["database"] = True
        except Exception:
            checks["database"] = False
        finally:
            try:
                db.close()
            except Exception:
                pass
        try:
            r = _get_redis_runtime()
            r.ping()
            checks["redis"] = True
        except Exception:
            checks["redis"] = False
        status = "ready" if all(checks.values()) else "not_ready"
        payload = {"status": status, "checks": checks}
        code = 200 if status == "ready" else 503
        return Response(json.dumps(payload, separators=(",", ":")), status=code, mimetype="application/json")

    app.register_blueprint(bp)
