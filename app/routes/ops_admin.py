from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Dict, List
from urllib.parse import urlencode

from flask import redirect, render_template, request, session, url_for
from flask_limiter.util import get_remote_address
from sqlalchemy import delete, func, select

from ..services.common import redact_proxy_credentials


def _runtime_attr(name: str, default: Any) -> Any:
    main_mod = sys.modules.get("app.main")
    if main_mod is not None and hasattr(main_mod, name):
        return getattr(main_mod, name)
    return default


def _admin_rate_limit_key() -> str:
    admin_user_id = str(session.get("admin_user_id") or "").strip()
    if admin_user_id:
        return f"admin:{admin_user_id}"
    return f"ip:{get_remote_address()}"


def register_ops_admin_routes(
    app,
    *,
    limiter,
    cfg,
    logger: logging.Logger,
    deps: Dict[str, Any],
) -> None:
    _admin_token_authorized = deps["_admin_token_authorized"]
    _app_log = deps["_app_log"]
    _apply_feed_filters_and_sort = deps["_apply_feed_filters_and_sort"]
    _audit = deps["_audit"]
    _build_feed_items = deps["_build_feed_items"]
    _db = deps["_db"]
    _enqueue_sync_job = deps["_enqueue_sync_job"]
    _ensure_default_feeds = deps["_ensure_default_feeds"]
    _feed_secret_key = deps["_feed_secret_key"]
    _feed_value_key = deps["_feed_value_key"]
    _fetch_mwdb_orgs = deps["_fetch_mwdb_orgs"]
    _get_feed_field_value = deps["_get_feed_field_value"]
    _get_setting = deps["_get_setting"]
    _mask_secret = deps["_mask_secret"]
    _parse_feed_table_params = deps["_parse_feed_table_params"]
    _read_feed_config_state = deps["_read_feed_config_state"]
    _read_feed_rows = deps["_read_feed_rows"]
    _run_proxy_test = deps["_run_proxy_test"]
    _set_setting = deps["_set_setting"]
    _source_templates = deps["_source_templates"]
    _test_feed_connection = deps["_test_feed_connection"]
    _validate_feed_form = deps["_validate_feed_form"]
    _write_proxy_env = deps["_write_proxy_env"]
    get_redis = deps["get_redis"]
    Indicator = deps["Indicator"]
    FeedStats = deps["FeedStats"]
    AppSetting = deps["AppSetting"]
    ExportJob = deps["ExportJob"]
    Feed = deps["Feed"]
    FeedRun = deps["FeedRun"]
    AppLog = deps["AppLog"]
    SyncJob = deps["SyncJob"]

    @app.get("/admin")
    @limiter.limit("100 per minute", key_func=_admin_rate_limit_key)
    def admin_panel():
        table_params = _parse_feed_table_params()
        db = _db()
        try:
            _ensure_default_feeds(db)
            all_feed_items = _build_feed_items(db)
            filtered_items = _apply_feed_filters_and_sort(
                all_feed_items,
                status_filter=str(table_params["status"]),
                datasource=str(table_params["datasource"]),
                configured=str(table_params["configured"]),
                query_text=str(table_params["q"]),
                problems_only=bool(table_params["problems_only"]),
                sort_by=str(table_params["sort"]),
                sort_order=str(table_params["order"]),
            )
            total_feeds = len(filtered_items)
            limit = int(table_params["limit"])
            offset = int(table_params["offset"])
            if offset >= total_feeds and total_feeds > 0:
                offset = max(0, ((total_feeds - 1) // max(1, limit)) * max(1, limit))
            page_feed_items = filtered_items[offset : offset + limit]
            datasource_options = sorted({str(item["source_type"]) for item in all_feed_items})
            feed_rows = db.scalars(select(FeedStats).order_by(FeedStats.source.asc(), FeedStats.source_id.asc())).all()
            raw_limit = min(200, max(10, int(request.args.get("raw_limit", "50"))))
            raw_offset = max(0, int(request.args.get("raw_offset", "0")))
            raw_total = len(feed_rows)
            if raw_offset >= raw_total and raw_total > 0:
                raw_offset = max(0, ((raw_total - 1) // raw_limit) * raw_limit)
            raw_page = list(feed_rows)[raw_offset : raw_offset + raw_limit]
            settings_count = int(db.scalar(select(func.count()).select_from(AppSetting)) or 0)
            proxy_conf = {
                "proxy_http_url": _get_setting(db, "proxy.http_url", os.getenv("HTTP_PROXY", "")),
                "proxy_https_url": _get_setting(db, "proxy.https_url", os.getenv("HTTPS_PROXY", "")),
                "proxy_no_proxy": _get_setting(db, "proxy.no_proxy", os.getenv("NO_PROXY", "")),
                "proxy_ca_bundle_path": _get_setting(db, "proxy.ca_bundle_path", os.getenv("REQUESTS_CA_BUNDLE", "")),
                "proxy_skip_tls_verify": _get_setting(db, "proxy.skip_tls_verify", os.getenv("REQUESTS_SKIP_TLS_VERIFY", "0")),
                "trusted_proxy_count": _get_setting(db, "proxy.trusted_proxy_count", os.getenv("TRUSTED_PROXY_COUNT", "0")),
                "sentinel_tenant_id": _get_setting(db, "sentinel.tenant_id", cfg.AZURE_SENTINEL_TENANT_ID),
                "sentinel_client_id": _get_setting(db, "sentinel.client_id", cfg.AZURE_SENTINEL_CLIENT_ID),
                "sentinel_auth_mode": _get_setting(db, "sentinel.auth_mode", cfg.AZURE_SENTINEL_AUTH_MODE),
                "sentinel_scope": _get_setting(db, "sentinel.scope", cfg.AZURE_SENTINEL_SCOPE),
                "sentinel_endpoint_url": _get_setting(db, "sentinel.endpoint_url", cfg.AZURE_SENTINEL_ENDPOINT_URL),
                "sentinel_chunk_size": _get_setting(db, "sentinel.chunk_size", str(cfg.AZURE_SENTINEL_CHUNK_SIZE)),
                "sentinel_cert_thumbprint": _get_setting(db, "sentinel.cert_thumbprint", cfg.AZURE_SENTINEL_CERT_THUMBPRINT),
                "sentinel_client_secret_masked": _mask_secret(
                    _get_setting(db, "sentinel.client_secret", cfg.AZURE_SENTINEL_CLIENT_SECRET, secret=True)
                ),
                "sentinel_cert_private_key_masked": _mask_secret(
                    _get_setting(db, "sentinel.cert_private_key_pem", cfg.AZURE_SENTINEL_CERT_PRIVATE_KEY_PEM, secret=True)
                ),
            }
            security_conf = {
                "admin_login_rate_limit": _get_setting(db, "feedcfg.security.admin_login_rate_limit", cfg.ADMIN_LOGIN_RATE_LIMIT),
                "admin_login_rate_limit_window_minutes": _get_setting(db, "feedcfg.security.admin_login_rate_limit_window_minutes", str(cfg.ADMIN_LOGIN_RATE_LIMIT_WINDOW_MINUTES)),
            }
            proxy_test_raw = _get_setting(db, "proxy.last_test_result", "")
            proxy_test_results: List[Dict[str, Any]] = []
            if proxy_test_raw:
                try:
                    parsed = json.loads(proxy_test_raw)
                    if isinstance(parsed, list):
                        proxy_test_results = [p for p in parsed if isinstance(p, dict)]
                except Exception:
                    proxy_test_results = []
            scheduler_heartbeat = _get_setting(db, "scheduler.heartbeat", "")
            recent_sync_jobs = list(db.scalars(select(SyncJob).order_by(SyncJob.created_at.desc()).limit(40)).all())
        finally:
            db.close()

        status_msg = request.args.get("msg", "")
        proxy_test_raw_json = json.dumps(proxy_test_results, ensure_ascii=True)

        def _admin_query(**kwargs: Any) -> str:
            q = {
                "feeds_limit": int(table_params["limit"]),
                "feeds_offset": int(offset),
                "feeds_sort": str(table_params["sort"]),
                "feeds_order": str(table_params["order"]),
                "feeds_status": str(table_params["status"]).lower(),
                "feeds_datasource": str(table_params["datasource"]),
                "feeds_configured": str(table_params["configured"]),
                "feeds_q": str(table_params["q"]),
                "feeds_problems_only": "1" if bool(table_params["problems_only"]) else "0",
            }
            for k, v in kwargs.items():
                q[str(k)] = v
            return urlencode(q)

        raw_prev_offset = max(0, raw_offset - raw_limit)
        raw_next_offset = raw_offset + raw_limit
        raw_has_prev = raw_offset > 0
        raw_has_next = raw_next_offset < raw_total
        raw_start = (raw_offset + 1) if raw_total > 0 else 0
        raw_end = min(raw_offset + raw_limit, raw_total)
        raw_prev_link = f"/admin?{_admin_query(raw_offset=raw_prev_offset, raw_limit=raw_limit)}"
        raw_next_link = f"/admin?{_admin_query(raw_offset=raw_next_offset, raw_limit=raw_limit)}"

        prev_offset = max(0, int(offset) - int(table_params["limit"]))
        next_offset = int(offset) + int(table_params["limit"])
        has_prev = int(offset) > 0
        has_next = next_offset < total_feeds
        page_start = (int(offset) + 1) if total_feeds > 0 else 0
        page_end = min(int(offset) + int(table_params["limit"]), total_feeds)
        prev_link = f"/admin?{_admin_query(feeds_offset=prev_offset)}"
        next_link = f"/admin?{_admin_query(feeds_offset=next_offset)}"

        return render_template(
            "admin/panel.html",
            settings_count=settings_count,
            scheduler_heartbeat=scheduler_heartbeat or "n/a",
            status_msg=status_msg,
            proxy_conf={k: str(v or "") for k, v in proxy_conf.items()},
            proxy_skip_tls_verify_checked=str(proxy_conf["proxy_skip_tls_verify"]).strip().lower() in {"1", "true", "yes", "on"},
            sentinel_certificate_selected=str(proxy_conf["sentinel_auth_mode"]).strip().lower() == "certificate",
            proxy_test_results=proxy_test_results,
            proxy_test_raw_json=proxy_test_raw_json,
            table_params=table_params,
            datasource_options=datasource_options,
            page_feed_items=page_feed_items,
            page_start=page_start,
            page_end=page_end,
            total_feeds=total_feeds,
            has_prev=has_prev,
            has_next=has_next,
            prev_link=prev_link,
            next_link=next_link,
            raw_page=raw_page,
            raw_start=raw_start,
            raw_end=raw_end,
            raw_total=raw_total,
            raw_has_prev=raw_has_prev,
            raw_has_next=raw_has_next,
            raw_prev_link=raw_prev_link,
            raw_next_link=raw_next_link,
            recent_sync_jobs=recent_sync_jobs,
            instance_name=cfg.INSTANCE_NAME,
            security_conf={k: str(v or "") for k, v in security_conf.items()},
        )

    @app.post("/admin/global-config")
    @limiter.limit("10 per minute", key_func=_admin_rate_limit_key)
    def admin_save_global_config():
        db = _db()
        try:
            _set_setting(db, "proxy.http_url", (request.form.get("proxy_http_url") or "").strip())
            _set_setting(db, "proxy.https_url", (request.form.get("proxy_https_url") or "").strip())
            _set_setting(db, "proxy.no_proxy", (request.form.get("proxy_no_proxy") or "").strip())
            _set_setting(db, "proxy.ca_bundle_path", (request.form.get("proxy_ca_bundle_path") or "").strip())
            _set_setting(
                db,
                "proxy.skip_tls_verify",
                "1" if (request.form.get("proxy_skip_tls_verify") or "").strip().lower() in {"1", "true", "yes", "on"} else "0",
            )
            _set_setting(db, "proxy.trusted_proxy_count", (request.form.get("trusted_proxy_count") or "0").strip())
            _set_setting(db, "sentinel.tenant_id", (request.form.get("sentinel_tenant_id") or "").strip())
            _set_setting(db, "sentinel.client_id", (request.form.get("sentinel_client_id") or "").strip())
            _set_setting(db, "sentinel.auth_mode", (request.form.get("sentinel_auth_mode") or "client_secret").strip().lower())
            _set_setting(db, "sentinel.scope", (request.form.get("sentinel_scope") or "").strip())
            _set_setting(db, "sentinel.endpoint_url", (request.form.get("sentinel_endpoint_url") or "").strip())
            _set_setting(db, "sentinel.chunk_size", (request.form.get("sentinel_chunk_size") or str(cfg.AZURE_SENTINEL_CHUNK_SIZE)).strip())
            _set_setting(db, "sentinel.cert_thumbprint", (request.form.get("sentinel_cert_thumbprint") or "").strip())
            sentinel_client_secret = (request.form.get("sentinel_client_secret") or "").strip()
            if sentinel_client_secret:
                _set_setting(db, "sentinel.client_secret", sentinel_client_secret, secret=True)
            sentinel_cert_private_key_pem = (request.form.get("sentinel_cert_private_key_pem") or "").strip()
            if sentinel_cert_private_key_pem:
                _set_setting(db, "sentinel.cert_private_key_pem", sentinel_cert_private_key_pem, secret=True)

            # Security settings (admin login rate limiting)
            admin_login_rate_limit = (request.form.get("admin_login_rate_limit") or "").strip()
            if admin_login_rate_limit:
                _set_setting(db, "feedcfg.security.admin_login_rate_limit", admin_login_rate_limit)
            admin_login_window = (request.form.get("admin_login_rate_limit_window_minutes") or "").strip()
            if admin_login_window:
                _set_setting(db, "feedcfg.security.admin_login_rate_limit_window_minutes", admin_login_window)

            db.commit()
            _write_proxy_env(db)
            _audit("admin_config_update", "app_settings", None, {"updated": True}, db=db)
            return redirect(url_for("admin_panel", msg="Global configuration saved."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Configuration save failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/proxy-test")
    @limiter.limit("10 per minute", key_func=_admin_rate_limit_key)
    def admin_proxy_test():
        db = _db()
        try:
            _write_proxy_env(db)
            results = _run_proxy_test()
            _set_setting(db, "proxy.last_test_result", json.dumps(results, separators=(",", ":")))
            db.commit()
            _audit("admin_proxy_test", "app_settings", None, {"targets": len(results)}, db=db)
            status = "ok" if all(str(r.get("status")) == "OK" for r in results) else "warning"
            return redirect(url_for("admin_panel", msg=f"Proxy test completed ({status})."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Proxy test failed: {redact_proxy_credentials(str(e))}"))
        finally:
            db.close()

    @app.post("/admin/danger/wipe")
    @limiter.limit("3 per hour", key_func=_admin_rate_limit_key)
    def admin_danger_wipe():
        if not _admin_token_authorized():
            return redirect(url_for("admin_panel", msg="Dangerous operation denied: invalid admin token."))
        confirm_phrase = (request.form.get("confirm_phrase") or "").strip().upper()
        confirm_instance = (request.form.get("confirm_instance") or "").strip()
        if confirm_phrase != "WIPE":
            return redirect(url_for("admin_panel", msg="Dangerous operation denied: confirmation phrase mismatch."))
        if confirm_instance != cfg.INSTANCE_NAME:
            return redirect(url_for("admin_panel", msg="Dangerous operation denied: instance name mismatch."))

        operation = (request.form.get("operation") or "soft").strip().lower()
        selected = [str(v).strip().lower() for v in request.form.getlist("tables") if str(v).strip()]
        table_models: Dict[str, Any] = {
            "indicators": Indicator,
            "feed_stats": FeedStats,
            "feed_runs": FeedRun,
            "sync_jobs": SyncJob,
            "app_logs": AppLog,
            "export_jobs": ExportJob,
            "feeds": Feed,
            "app_settings": AppSetting,
        }
        soft_tables = ["indicators", "feed_stats", "feed_runs", "sync_jobs", "app_logs", "export_jobs"]
        factory_tables = soft_tables + ["feeds", "app_settings"]
        if operation == "soft":
            target_tables = soft_tables
        elif operation == "factory":
            target_tables = factory_tables
        elif operation == "selected":
            target_tables = [t for t in selected if t in table_models]
            if not target_tables:
                return redirect(url_for("admin_panel", msg="Dangerous operation denied: no valid tables selected."))
        else:
            return redirect(url_for("admin_panel", msg="Dangerous operation denied: invalid operation."))

        db = _db()
        deleted: Dict[str, int] = {}
        cache_flushed = False
        try:
            for table_name in target_tables:
                model = table_models[table_name]
                before_count = int(db.scalar(select(func.count()).select_from(model)) or 0)
                db.execute(delete(model))
                deleted[table_name] = before_count
            db.commit()
            try:
                r = _runtime_attr("get_redis", get_redis)()
                r.flushdb()
                cache_flushed = True
            except Exception:
                cache_flushed = False
            _audit(
                "admin_wipe",
                "system",
                None,
                {
                    "operation": operation,
                    "instance": cfg.INSTANCE_NAME,
                    "deleted": deleted,
                    "cache_flushed": cache_flushed,
                },
                db=db,
            )
            return redirect(
                url_for("admin_panel", msg=f"Dangerous operation completed ({operation}). Deleted tables: {', '.join(sorted(deleted.keys()))}.")
            )
        except Exception as e:
            db.rollback()
            logger.exception("admin_danger_wipe_failed")
            return redirect(url_for("admin_panel", msg=f"Dangerous operation failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed/new")
    @limiter.limit("10 per minute", key_func=_admin_rate_limit_key)
    def admin_add_feed():
        source_id = (request.form.get("source_id") or "").strip().lower()
        display_name = (request.form.get("display_name") or "").strip()
        source_type = (request.form.get("source_type") or "").strip().lower()
        base_url = (request.form.get("base_url") or "").strip() or None
        auth_type = (request.form.get("auth_type") or "").strip() or None
        schedule_cron = (request.form.get("schedule_cron") or "*/15 * * * *").strip()
        enabled = (request.form.get("enabled") or "").strip().lower() in {"1", "true", "yes", "on"}
        if not source_id or not display_name or source_type not in set(_source_templates().keys()):
            return redirect(url_for("admin_panel", msg="Invalid feed definition."))
        db = _db()
        try:
            _ensure_default_feeds(db)
            existing = db.scalar(select(Feed).where(Feed.source_id == source_id))
            if existing and not existing.deleted:
                return redirect(url_for("admin_panel", msg=f"Feed {source_id} already exists."))
            if existing and existing.deleted:
                existing.deleted = False
                existing.display_name = display_name
                existing.source_type = source_type
                existing.base_url = base_url
                existing.auth_type = auth_type
                existing.schedule_cron = schedule_cron
                existing.enabled = enabled
            else:
                db.add(
                    Feed(
                        source_id=source_id,
                        source_type=source_type,
                        display_name=display_name,
                        base_url=base_url,
                        auth_type=auth_type,
                        schedule_cron=schedule_cron,
                        enabled=enabled,
                        deleted=False,
                    )
                )
            db.commit()
            persisted = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            _audit(
                "admin_feed_add",
                "feed",
                int(getattr(persisted, "id", 0) or 0) or None,
                {"source": source_id, "source_type": source_type, "enabled": enabled},
                db=db,
            )
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} added."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Add feed failed: {e}"))
        finally:
            db.close()

    @app.get("/admin/feed/<source_id>/configure")
    @limiter.limit("100 per minute", key_func=_admin_rate_limit_key)
    def admin_feed_configure(source_id: str):
        source_id = (source_id or "").strip().lower()
        msg = (request.args.get("msg") or "").strip()
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Feed not found."))
            state = _read_feed_config_state(db, feed)
            mwdb_orgs: List[Dict[str, str]] = []
            mwdb_selected_orgs: List[str] = []
            mwdb_selected_group: str = ""
            if feed.source_type == "mwdb":
                mwdb_selected_orgs = [x.strip() for x in _get_setting(db, _feed_value_key(feed.source_id, "organizations"), "").split(",") if x.strip()]
                mwdb_selected_group = _get_setting(db, _feed_value_key(feed.source_id, "my_group"), "", secret=False)
                values = {str(f["key"]): _get_feed_field_value(db, feed, f) for f in state["fields"]}
                mwdb_orgs = _fetch_mwdb_orgs(values.get("base_url", ""), values.get("api_key", ""))
        finally:
            db.close()
        return render_template(
            "admin/feed_configure.html",
            source_id=source_id,
            msg=msg,
            feed=feed,
            state=state,
            mwdb_orgs=mwdb_orgs,
            mwdb_selected_orgs=mwdb_selected_orgs,
            mwdb_selected_group=mwdb_selected_group,
        )

    @app.post("/admin/feed/<source_id>/configure")
    @limiter.limit("10 per minute", key_func=_admin_rate_limit_key)
    def admin_feed_configure_save(source_id: str):
        source_id = (source_id or "").strip().lower()
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Feed not found."))
            feed.display_name = (request.form.get("display_name") or feed.display_name).strip() or feed.display_name
            feed.base_url = (request.form.get("base_url") or "").strip() or None
            feed.schedule_cron = (request.form.get("schedule_cron") or "*/15 * * * *").strip()
            state = _read_feed_config_state(db, feed)
            errors = _validate_feed_form(feed, request.form, state, db)
            for f in state["fields"]:
                input_name = str(f["input_name"])
                incoming = (request.form.get(input_name) or "").strip()
                if f["key"] == "base_url":
                    continue
                if f.get("secret"):
                    if incoming:
                        _set_setting(db, _feed_secret_key(feed.source_id, str(f["key"])), incoming, secret=True)
                    elif f.get("required") and not _get_setting(db, _feed_secret_key(feed.source_id, str(f["key"])), "", secret=True):
                        errors.append(f"Missing required field: {f['label']}")
                else:
                    normalized = incoming
                    if str(f.get("type") or "") == "checkbox":
                        normalized = "1" if incoming.lower() in {"1", "true", "yes", "on"} else "0"
                    _set_setting(db, _feed_value_key(feed.source_id, str(f["key"])), normalized, secret=False)
            if feed.source_type == "mwdb":
                orgs = [x.strip() for x in request.form.getlist("mwdb_orgs") if x.strip()]
                _set_setting(db, _feed_value_key(feed.source_id, "organizations"), ",".join(orgs), secret=False)
                my_grp = (request.form.get("mwdb_my_group") or "").strip()
                _set_setting(db, _feed_value_key(feed.source_id, "my_group"), my_grp, secret=False)
            if errors:
                db.rollback()
                return redirect(url_for("admin_feed_configure", source_id=source_id, msg=f"Validation failed: {' '.join(errors)}"))
            db.commit()
            _audit(
                "admin_feed_configure_save",
                "feed",
                int(getattr(feed, "id", 0) or 0) or None,
                {
                    "source": source_id,
                    "source_type": feed.source_type,
                    "schedule_cron": feed.schedule_cron,
                },
                db=db,
            )
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} configuration saved."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Configure feed failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed/<source_id>/test")
    @limiter.limit("10 per minute", key_func=_admin_rate_limit_key)
    def admin_feed_test_connection(source_id: str):
        source_id = (source_id or "").strip().lower()
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Feed not found."))
            state = _read_feed_config_state(db, feed)
            field_values: Dict[str, str] = {}
            for f in state["fields"]:
                field_values[str(f["key"])] = _get_feed_field_value(db, feed, f, request.form)
            if feed.source_type == "mwdb":
                selected_orgs = [x.strip() for x in request.form.getlist("mwdb_orgs") if x.strip()]
                field_values["organizations"] = ",".join(selected_orgs)
            ok, msg = _test_feed_connection(feed, field_values)
            status = "OK" if ok else "FAILED"
            _audit(
                "admin_feed_test_connection",
                "feed",
                int(getattr(feed, "id", 0) or 0) or None,
                {"source": source_id, "status": status.lower(), "message": msg},
                db=db,
            )
            return redirect(url_for("admin_feed_configure", source_id=source_id, msg=f"Connection test {status}: {msg}"))
        except Exception as e:
            return redirect(url_for("admin_feed_configure", source_id=source_id, msg=f"Connection test failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed-toggle")
    @limiter.limit("10 per minute", key_func=_admin_rate_limit_key)
    def admin_feed_toggle():
        source_name = (request.form.get("source") or "").strip().lower()
        enabled = (request.form.get("enabled") or "").strip().lower() in {"1", "true", "yes", "on"}
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_name, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Invalid source for feed toggle."))
            feed.enabled = enabled
            db.commit()
            _audit("admin_feed_toggle", "feed", None, {"source": source_name, "enabled": enabled}, db=db)
            return redirect(url_for("admin_panel", msg=f"Feed {source_name} {'enabled' if enabled else 'disabled'}"))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Feed toggle failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed/<source_id>/delete")
    @limiter.limit("10 per minute", key_func=_admin_rate_limit_key)
    def admin_feed_delete(source_id: str):
        source_id = (source_id or "").strip().lower()
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed = db.scalar(select(Feed).where(Feed.source_id == source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg="Feed not found."))
            feed.deleted = True
            feed.enabled = False
            db.commit()
            _audit(
                "admin_feed_delete",
                "feed",
                int(getattr(feed, "id", 0) or 0) or None,
                {"source": source_id},
                db=db,
            )
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} deleted (soft)."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Delete feed failed: {e}"))
        finally:
            db.close()
