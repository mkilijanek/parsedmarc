from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from urllib.parse import urlencode

from flask import jsonify, redirect, request, url_for
from sqlalchemy import delete, func, select

from ..services.common import redact_proxy_credentials


def _runtime_attr(name: str, default: Any) -> Any:
    main_mod = sys.modules.get("app.main")
    if main_mod is not None and hasattr(main_mod, name):
        return getattr(main_mod, name)
    return default


def register_ops_routes(
    app,
    *,
    limiter,
    cfg,
    logger: logging.Logger,
    scheduler_state: Dict[str, Any],
    deps: Dict[str, Any],
) -> None:
    _admin_dangerous_ops_enabled = deps["_admin_dangerous_ops_enabled"]
    _admin_token_authorized = deps["_admin_token_authorized"]
    _app_log = deps["_app_log"]
    _apply_feed_filters_and_sort = deps["_apply_feed_filters_and_sort"]
    _audit = deps["_audit"]
    _build_feed_items = deps["_build_feed_items"]
    _db = deps["_db"]
    _enqueue_sync_job = deps["_enqueue_sync_job"]
    _ensure_default_feeds = deps["_ensure_default_feeds"]
    _esc = deps["_esc"]
    _feed_secret_key = deps["_feed_secret_key"]
    _feed_value_key = deps["_feed_value_key"]
    _fetch_mwdb_orgs = deps["_fetch_mwdb_orgs"]
    _get_feed_field_value = deps["_get_feed_field_value"]
    _get_setting = deps["_get_setting"]
    _mask_secret = deps["_mask_secret"]
    _parse_feed_table_params = deps["_parse_feed_table_params"]
    _percentile = deps["_percentile"]
    _read_feed_config_state = deps["_read_feed_config_state"]
    _read_feed_rows = deps["_read_feed_rows"]
    _resolve_metrics_window_hours = deps["_resolve_metrics_window_hours"]
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
    ADMIN_FEED_METRICS_WIDGET_HTML = deps["ADMIN_FEED_METRICS_WIDGET_HTML"]
    ADMIN_FEED_METRICS_WIDGET_SCRIPT = deps["ADMIN_FEED_METRICS_WIDGET_SCRIPT"]

    @app.get("/admin")
    @limiter.limit("30 per minute")
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
                "sentinel_client_secret_masked": _mask_secret(_get_setting(db, "sentinel.client_secret", cfg.AZURE_SENTINEL_CLIENT_SECRET, secret=True)),
                "sentinel_cert_private_key_masked": _mask_secret(_get_setting(db, "sentinel.cert_private_key_pem", cfg.AZURE_SENTINEL_CERT_PRIVATE_KEY_PEM, secret=True)),
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
        proxy_test_rows_html = "".join(
            [
                (
                    "<tr>"
                    f"<td>{_esc(str(row.get('target') or ''))}</td>"
                    f"<td>{_esc(str(row.get('status') or ''))}</td>"
                    f"<td>{_esc(str(row.get('http') if row.get('http') is not None else '-'))}</td>"
                    f"<td>{_esc(str(row.get('latency_ms') if row.get('latency_ms') is not None else '-'))}</td>"
                    f"<td>{_esc(str(row.get('title') or ''))}</td>"
                    f"<td>{_esc(str(row.get('notes') or ''))}</td>"
                    "</tr>"
                )
                for row in proxy_test_results
            ]
        )
        if not proxy_test_rows_html:
            proxy_test_rows_html = "<tr><td colspan='6'>No proxy test results yet.</td></tr>"
        proxy_test_raw_json = _esc(json.dumps(proxy_test_results, ensure_ascii=True))
        feed_rows_html = "".join(
            [
                (
                    "<tr>"
                    f"<td>{_esc(str(row.source))}</td>"
                    f"<td>{_esc(str(row.source_id or ''))}</td>"
                    f"<td>{_esc(str(row.last_fetch_status or ''))}</td>"
                    f"<td>{_esc(str(row.last_update or ''))}</td>"
                    f"<td>{_esc(str(row.last_fetch_error or ''))}</td>"
                    "</tr>"
                )
                for row in raw_page
            ]
        )
        if not feed_rows_html:
            feed_rows_html = "<tr><td colspan='5'>No feed statistics yet.</td></tr>"

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
        raw_prev_html = f"<a href='{raw_prev_link}'>Previous</a>" if raw_has_prev else "Previous"
        raw_next_html = f"<a href='{raw_next_link}'>Next</a>" if raw_has_next else "Next"
        raw_pager_html = f"<p><strong>Raw stats:</strong> showing {raw_start}-{raw_end} of {raw_total}. {raw_prev_html} | {raw_next_html}</p>"

        source_ctrl_html = "".join(
            [
                (
                    "<tr>"
                    f"<td><code>{_esc(item['source_id'])}</code><br/>{_esc(item['display_name'])}<br/><small>{_esc(item['source_type'])}</small></td>"
                    f"<td>{'enabled' if item['enabled'] else 'disabled'}</td>"
                    f"<td>{_esc(item['schedule_cron'])}</td>"
                    f"<td>{'OK' if item['ready'] else 'Incomplete: ' + _esc(', '.join(item['missing']))}</td>"
                    f"<td>{_esc(item['last_run_status'])}</td>"
                    f"<td>{_esc(str(item['last_run_at'] or 'n/a'))}</td>"
                    f"<td><form method='post' action='/admin/feed-toggle' style='display:inline'>"
                    f"<input type='hidden' name='source' value='{_esc(item['source_id'])}'/>"
                    f"<input type='hidden' name='enabled' value='{'0' if item['enabled'] else '1'}'/>"
                    f"<button type='submit'>{'Disable' if item['enabled'] else 'Enable'}</button>"
                    "</form> "
                    f"<a href='/admin/feed/{_esc(item['source_id'])}/configure'>Configure</a> "
                    f"<form method='post' action='/admin/sync' style='display:inline'>"
                    f"<input type='hidden' name='source' value='{_esc(item['source_id'])}'/>"
                    f"<button type='submit' {'disabled' if not item['ready'] else ''}>Sync now</button>"
                    "</form> "
                    f"<a href='/logs?feed={_esc(item['source_id'])}'>View logs</a> "
                    f"<form method='post' action='/admin/feed/{_esc(item['source_id'])}/delete' style='display:inline' onsubmit='return confirm(\"Delete feed {_esc(item['source_id'])}?\")'>"
                    "<button type='submit'>Delete</button>"
                    "</form></td>"
                    "</tr>"
                )
                for item in page_feed_items
            ]
        )
        if not source_ctrl_html:
            source_ctrl_html = "<tr><td colspan='7'>No feeds match current filters.</td></tr>"

        prev_offset = max(0, int(offset) - int(table_params["limit"]))
        next_offset = int(offset) + int(table_params["limit"])
        has_prev = int(offset) > 0
        has_next = next_offset < total_feeds
        page_start = (int(offset) + 1) if total_feeds > 0 else 0
        page_end = min(int(offset) + int(table_params["limit"]), total_feeds)
        prev_link_html = f"<a href='/admin?{_admin_query(feeds_offset=prev_offset)}'>Previous</a>" if has_prev else "Previous"
        next_link_html = f"<a href='/admin?{_admin_query(feeds_offset=next_offset)}'>Next</a>" if has_next else "Next"

        feed_filter_controls = f"""
        <form method='get' action='/admin' style='display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.5rem;align-items:end;margin:.7rem 0 1rem'>
          <label>Status
            <select name='feeds_status'>
              <option value='all' {'selected' if str(table_params['status']) == 'ALL' else ''}>all</option>
              <option value='ok' {'selected' if str(table_params['status']) == 'OK' else ''}>OK</option>
              <option value='warning' {'selected' if str(table_params['status']) == 'WARNING' else ''}>WARNING</option>
              <option value='error' {'selected' if str(table_params['status']) == 'ERROR' else ''}>ERROR</option>
              <option value='disabled' {'selected' if str(table_params['status']) == 'DISABLED' else ''}>DISABLED</option>
              <option value='not_configured' {'selected' if str(table_params['status']) == 'NOT_CONFIGURED' else ''}>NOT_CONFIGURED</option>
            </select>
          </label>
          <label>Datasource
            <select name='feeds_datasource'>
              <option value='all' {'selected' if str(table_params['datasource']) in {'', 'all'} else ''}>all</option>
              {''.join([f"<option value='{_esc(src)}' {'selected' if str(table_params['datasource']) == src else ''}>{_esc(src)}</option>" for src in datasource_options])}
            </select>
          </label>
          <label>Configured
            <select name='feeds_configured'>
              <option value='all' {'selected' if str(table_params['configured']) == 'all' else ''}>all</option>
              <option value='configured' {'selected' if str(table_params['configured']) == 'configured' else ''}>configured</option>
              <option value='not_configured' {'selected' if str(table_params['configured']) == 'not_configured' else ''}>not configured</option>
            </select>
          </label>
          <label>Search
            <input type='text' name='feeds_q' value='{_esc(str(table_params['q']))}' placeholder='feed name / source id'/>
          </label>
          <label>Sort
            <select name='feeds_sort'>
              <option value='source' {'selected' if str(table_params['sort']) == 'source' else ''}>source</option>
              <option value='status' {'selected' if str(table_params['sort']) == 'status' else ''}>status</option>
              <option value='last_run_at' {'selected' if str(table_params['sort']) == 'last_run_at' else ''}>last_run_at</option>
              <option value='last_error_at' {'selected' if str(table_params['sort']) == 'last_error_at' else ''}>last_error_at</option>
              <option value='fetched_count' {'selected' if str(table_params['sort']) == 'fetched_count' else ''}>fetched_count</option>
            </select>
          </label>
          <label>Order
            <select name='feeds_order'>
              <option value='asc' {'selected' if str(table_params['order']) == 'asc' else ''}>asc</option>
              <option value='desc' {'selected' if str(table_params['order']) == 'desc' else ''}>desc</option>
            </select>
          </label>
          <label>Per page
            <select name='feeds_limit'>
              <option value='25' {'selected' if int(table_params['limit']) == 25 else ''}>25</option>
              <option value='50' {'selected' if int(table_params['limit']) == 50 else ''}>50</option>
              <option value='100' {'selected' if int(table_params['limit']) == 100 else ''}>100</option>
            </select>
          </label>
          <label style='display:flex;align-items:center;gap:.5rem'>
            <input type='checkbox' name='feeds_problems_only' value='1' {'checked' if bool(table_params['problems_only']) else ''}/> Problems only
          </label>
          <input type='hidden' name='feeds_offset' value='0'/>
          <div style='display:flex;gap:.5rem'>
            <button type='submit'>Apply filters</button>
            <a href='/admin'>Clear</a>
          </div>
        </form>
        <p><strong>Feeds:</strong> showing {page_start}-{page_end} of {total_feeds} (server-side)</p>
        <p>
          {prev_link_html} |
          {next_link_html}
        </p>
        """

        recent_jobs_html = "".join(
            [
                (
                    "<tr>"
                    f"<td><code>{_esc(j.job_id)}</code></td>"
                    f"<td>{_esc(j.feed_source_id)}</td>"
                    f"<td>{_esc(j.trigger_type)}</td>"
                    f"<td>{_esc(j.status)}</td>"
                    f"<td>{_esc(str(j.created_at or ''))}</td>"
                    f"<td>{_esc(str(j.started_at or ''))}</td>"
                    f"<td>{_esc(str(j.finished_at or ''))}</td>"
                    "<td>"
                    f"<a href='/admin/sync-jobs/{_esc(j.job_id)}'>Details</a> "
                    + (
                        f"<form method='post' action='/admin/sync-jobs/{_esc(j.job_id)}/retry' style='display:inline'>"
                        "<button type='submit'>Retry</button></form> "
                        if str(j.status or "").lower() in {"failed", "cancelled"}
                        else ""
                    )
                    + (
                        f"<form method='post' action='/admin/sync-jobs/{_esc(j.job_id)}/cancel' style='display:inline'>"
                        "<button type='submit'>Cancel</button></form>"
                        if str(j.status or "").lower() in {"queued", "running", "cancel_requested"}
                        else ""
                    )
                    + "</td>"
                    "</tr>"
                )
                for j in recent_sync_jobs
            ]
        )
        if not recent_jobs_html:
            recent_jobs_html = "<tr><td colspan='8'>No sync jobs yet.</td></tr>"

        if _admin_dangerous_ops_enabled():
            danger_zone_html = f"""
  <div class="card">
    <h2>Danger Zone</h2>
    <p>High-risk operations. Requires admin token, confirmation phrase and instance name.</p>
    <form method="post" action="/admin/danger/wipe">
      <p><label>Operation
        <select name="operation">
          <option value="soft">Soft reset (indicators, runs, logs, stats, jobs, cache)</option>
          <option value="factory">Factory reset (all dynamic + feeds/settings)</option>
          <option value="selected">Selected tables</option>
        </select>
      </label></p>
      <fieldset>
        <legend>Selected tables (used when operation=selected)</legend>
        <label><input type="checkbox" name="tables" value="indicators"/> indicators</label>
        <label><input type="checkbox" name="tables" value="feed_stats"/> feed_stats</label>
        <label><input type="checkbox" name="tables" value="feed_runs"/> feed_runs</label>
        <label><input type="checkbox" name="tables" value="sync_jobs"/> sync_jobs</label>
        <label><input type="checkbox" name="tables" value="app_logs"/> app_logs</label>
        <label><input type="checkbox" name="tables" value="export_jobs"/> export_jobs</label>
        <label><input type="checkbox" name="tables" value="feeds"/> feeds</label>
        <label><input type="checkbox" name="tables" value="app_settings"/> app_settings</label>
      </fieldset>
      <p><label>Admin token <input type="password" name="admin_token" placeholder="ADMIN_API_TOKEN" required/></label></p>
      <p><label>Type confirmation <input type="text" name="confirm_phrase" placeholder="WIPE" required/></label></p>
      <p><label>Instance name <input type="text" name="confirm_instance" placeholder="{_esc(cfg.INSTANCE_NAME)}" required/></label></p>
      <button type="submit">Execute wipe</button>
    </form>
  </div>
            """
        else:
            danger_zone_html = """
  <div class="card">
    <h2>Danger Zone</h2>
    <p>Disabled. Set <code>ADMIN_DANGEROUS_OPS=true</code> and configure <code>ADMIN_API_TOKEN</code> to enable controlled wipe operations.</p>
  </div>
            """

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Admin Controls</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }}
    body[data-theme="light"] {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
    body[data-theme="dark"] {{ --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }}
    body:not([data-theme]) {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
    .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }}
    .topbar nav a {{ margin-right:.8rem; }}
    .card {{ border: 1px solid var(--line); border-radius: 16px; padding: 1rem; margin-bottom: 1rem; background: var(--card); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: .5rem; text-align: left; vertical-align: top; }}
    input[type=text], input[type=password], select {{ width: 100%; padding: .45rem; border-radius: 8px; border: 1px solid var(--line); background: var(--bg); color: var(--fg); }}
    button {{ padding: .5rem .8rem; border-radius: 8px; border: 1px solid var(--line); background: var(--card); color: var(--fg); }}
    fieldset {{ border: 1px solid var(--line); border-radius: 12px; margin: .75rem 0; padding: .75rem; }}
    .toast {{ border:1px solid var(--line); border-radius:10px; padding:.55rem .7rem; margin:.5rem 0 1rem; background:var(--card); }}
    .status-chip {{ display:inline-block; border:1px solid var(--line); border-radius:999px; font-size:.75rem; font-weight:600; padding:.15rem .5rem; white-space:nowrap; }}
    .status-chip.ok {{ background:#ecfdf3; color:#166534; }}
    .status-chip.warning {{ background:#fffbeb; color:#92400e; }}
    .status-chip.error {{ background:#fef2f2; color:#991b1b; }}
    .status-chip.disabled {{ background:#f1f5f9; color:#334155; }}
    .status-chip.not_configured {{ background:#fdf4ff; color:#7e22ce; }}
    .metrics-grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:.6rem; margin:.75rem 0; }}
    .metric-card {{ border:1px solid var(--line); border-radius:10px; padding:.55rem .7rem; }}
    .metric-card .label {{ font-size:.8rem; opacity:.75; }}
    .metric-card .value {{ font-size:1.05rem; font-weight:700; }}
    .mini-chart-wrap {{ border:1px solid var(--line); border-radius:10px; padding:.4rem; margin:.55rem 0 .75rem; }}
    .mini-chart-wrap svg {{ width:100%; height:120px; display:block; }}
  </style>
</head>
<body>
  <header class="topbar" id="globalTopbar">
    <nav>
      <a href="/">Overview</a>
      <a href="/indicators">Indicators</a>
      <a href="/admin">Admin</a>
      <a href="/logs">Logs</a>
    </nav>
    <button type="button" id="themeToggleGlobal">Toggle dark mode</button>
  </header>
  <h1>Admin Controls</h1>
  <p><strong>Stored settings:</strong> {settings_count}</p>
  <p><strong>Scheduler heartbeat:</strong> {_esc(scheduler_heartbeat or 'n/a')}</p>
  <div id="statusToast" class="toast" role="status" aria-live="polite">{_esc(status_msg)}</div>

  <div class="card">
    <h2>Configuration Panel (Global)</h2>
    <form method="post" action="/admin/global-config">
      <h3>Proxy Configuration</h3>
      <p><label>HTTP proxy <input type="text" name="proxy_http_url" value="{_esc(proxy_conf['proxy_http_url'])}" placeholder="http://proxy:8080"/></label></p>
      <p><label>HTTPS proxy <input type="text" name="proxy_https_url" value="{_esc(proxy_conf['proxy_https_url'])}" placeholder="http://proxy:8080"/></label></p>
      <p><label>No proxy list <input type="text" name="proxy_no_proxy" value="{_esc(proxy_conf['proxy_no_proxy'])}" placeholder="localhost,127.0.0.1,.internal"/></label></p>
      <p><label>Organization CA bundle path <input type="text" name="proxy_ca_bundle_path" value="{_esc(proxy_conf['proxy_ca_bundle_path'])}" placeholder="/etc/ssl/certs/org-ca.pem"/></label></p>
      <p><label><input type="checkbox" name="proxy_skip_tls_verify" value="1" {"checked" if str(proxy_conf['proxy_skip_tls_verify']).strip().lower() in {"1","true","yes","on"} else ""}/> Skip TLS certificate verification for outbound HTTP requests (insecure, curl -k equivalent)</label></p>
      <p><label>Trusted proxy count <input type="text" name="trusted_proxy_count" value="{_esc(proxy_conf['trusted_proxy_count'])}" placeholder="0"/></label></p>
      <h3>Azure Sentinel (Microsoft Graph)</h3>
      <p><label>Tenant ID <input type="text" name="sentinel_tenant_id" value="{_esc(proxy_conf['sentinel_tenant_id'])}" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/></label></p>
      <p><label>Client ID <input type="text" name="sentinel_client_id" value="{_esc(proxy_conf['sentinel_client_id'])}" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/></label></p>
      <p><label>Auth mode
        <select name="sentinel_auth_mode">
          <option value="client_secret" {"selected" if str(proxy_conf['sentinel_auth_mode']).strip().lower() != "certificate" else ""}>client_secret</option>
          <option value="certificate" {"selected" if str(proxy_conf['sentinel_auth_mode']).strip().lower() == "certificate" else ""}>certificate</option>
        </select>
      </label></p>
      <p><label>Client secret (leave blank to keep current: {_esc(proxy_conf['sentinel_client_secret_masked'])}) <input type="password" name="sentinel_client_secret" value="" placeholder="Leave blank to keep current"/></label></p>
      <p><label>Certificate private key PEM (leave blank to keep current: {_esc(proxy_conf['sentinel_cert_private_key_masked'])}) <input type="password" name="sentinel_cert_private_key_pem" value="" placeholder="-----BEGIN PRIVATE KEY-----"/></label></p>
      <p><label>Certificate thumbprint <input type="text" name="sentinel_cert_thumbprint" value="{_esc(proxy_conf['sentinel_cert_thumbprint'])}" placeholder="hex thumbprint"/></label></p>
      <p><label>Graph scope <input type="text" name="sentinel_scope" value="{_esc(proxy_conf['sentinel_scope'])}" placeholder="https://graph.microsoft.com/.default"/></label></p>
      <p><label>Graph endpoint URL <input type="text" name="sentinel_endpoint_url" value="{_esc(proxy_conf['sentinel_endpoint_url'])}" placeholder="https://graph.microsoft.com/beta/security/tiIndicators/submitTiIndicators"/></label></p>
      <p><label>Chunk size <input type="text" name="sentinel_chunk_size" value="{_esc(proxy_conf['sentinel_chunk_size'])}" placeholder="100"/></label></p>
      <button type="submit">Save configuration</button>
    </form>
    <form method="post" action="/admin/proxy-test" style="margin-top:.8rem">
      <button type="submit">Test proxy</button>
    </form>
    <h3>Proxy Test Results</h3>
    <table>
      <thead><tr><th>Target</th><th>Status</th><th>HTTP</th><th>Latency ms</th><th>Title</th><th>Notes</th></tr></thead>
      <tbody>{proxy_test_rows_html}</tbody>
    </table>
    <details style="margin-top:.6rem">
      <summary>Raw results</summary>
      <pre id="proxyTestRaw">{proxy_test_raw_json}</pre>
    </details>
    <button type="button" id="copyProxyResultsBtn">Copy results</button>
    <p><strong>Sentinel quick export:</strong>
      <code>curl -X POST /api/sentinel/export?q=source:mwdb&amp;type=all&amp;tlp=all</code>
    </p>
  </div>

  <div class="card">
    <h2>Manual Synchronization and Feed Management</h2>
    <h3>Add New Feed</h3>
    <form method="post" action="/admin/feed/new">
      <p><label>source_id <input type="text" name="source_id" placeholder="custom-feed-1" required></label></p>
      <p><label>display_name <input type="text" name="display_name" placeholder="Custom Feed" required></label></p>
      <p><label>source_type <input type="text" name="source_type" placeholder="misp|crowdsec|malwarebazaar|mwdb|abusech" required></label></p>
      <p><label>base_url <input type="text" name="base_url" placeholder="https://source.example.local"></label></p>
      <p><label>auth_type <input type="text" name="auth_type" placeholder="api_key"></label></p>
      <p><label>schedule_cron <input type="text" name="schedule_cron" value="*/15 * * * *"></label></p>
      <p><label><input type="checkbox" name="enabled" value="1" checked> enabled</label></p>
      <button type="submit">Add feed</button>
    </form>
    <form method="post" action="/admin/sync">
      <input type="hidden" name="source" value="all"/>
      <button type="submit">Sync all enabled sources</button>
    </form>
    {feed_filter_controls}
    <table>
      <thead><tr><th>Source</th><th>Enabled</th><th>Schedule</th><th>Config Readiness</th><th>Last Run Status</th><th>Last Run At</th><th>Actions</th></tr></thead>
      <tbody>{source_ctrl_html}</tbody>
    </table>
  </div>

  {ADMIN_FEED_METRICS_WIDGET_HTML}
  <div class="card">
    <h2>Feed Statistics (Raw Last Status)</h2>
    {raw_pager_html}
    <table>
      <thead><tr><th>Source</th><th>Source ID</th><th>Last Status</th><th>Last Update</th><th>Last Error</th></tr></thead>
      <tbody>{feed_rows_html}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Recent Sync Jobs</h2>
    <table>
      <thead><tr><th>Job ID</th><th>Source</th><th>Trigger</th><th>Status</th><th>Created</th><th>Started</th><th>Finished</th><th>Actions</th></tr></thead>
      <tbody>{recent_jobs_html}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Logs</h2>
    <p><a href="/logs">Open logs tab</a></p>
  </div>
  {danger_zone_html}
  <script>
    const themeKey = 'ioc-theme';
    const preferredTheme = localStorage.getItem(themeKey);
    if (preferredTheme === 'dark' || preferredTheme === 'light') {{
      document.body.setAttribute('data-theme', preferredTheme);
    }}
    const themeToggle = document.getElementById('themeToggleGlobal');
    if (themeToggle) {{
      themeToggle.addEventListener('click', () => {{
        const curr = document.body.getAttribute('data-theme') || 'light';
        const next = curr === 'dark' ? 'light' : 'dark';
        document.body.setAttribute('data-theme', next);
        localStorage.setItem(themeKey, next);
      }});
    }}
    const toast = document.getElementById('statusToast');
    if (toast && !toast.textContent.trim()) {{
      toast.style.display = 'none';
    }}
    document.querySelectorAll('form').forEach((form) => {{
      form.addEventListener('submit', (evt) => {{
        const submitter = evt.submitter;
        const buttons = form.querySelectorAll('button[type="submit"]');
        buttons.forEach((btn) => btn.disabled = true);
        if (submitter) {{
          submitter.dataset.originalText = submitter.textContent || '';
          submitter.textContent = 'Processing...';
        }}
      }});
    }});
    const copyProxyResultsBtn = document.getElementById('copyProxyResultsBtn');
    if (copyProxyResultsBtn) {{
      copyProxyResultsBtn.addEventListener('click', async () => {{
        const raw = document.getElementById('proxyTestRaw');
        const txt = raw ? raw.textContent || '' : '';
        try {{
          if (navigator.clipboard && window.isSecureContext) {{
            await navigator.clipboard.writeText(txt);
          }} else {{
            const ta = document.createElement('textarea');
            ta.value = txt;
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
          }}
          alert('Proxy test results copied.');
        }} catch (e) {{
          alert('Copy failed.');
        }}
      }});
    }}
    {ADMIN_FEED_METRICS_WIDGET_SCRIPT}
  </script>
</body>
</html>
"""

    @app.post("/admin/global-config")
    @limiter.limit("20 per minute")
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

            db.commit()
            _write_proxy_env(db)
            _audit("admin_config_update", "app_settings", None, {"updated": True})
            return redirect(url_for("admin_panel", msg="Global configuration saved."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Configuration save failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/proxy-test")
    @limiter.limit("10 per minute")
    def admin_proxy_test():
        db = _db()
        try:
            _write_proxy_env(db)
            results = _run_proxy_test()
            _set_setting(db, "proxy.last_test_result", json.dumps(results, separators=(",", ":")))
            db.commit()
            _audit("admin_proxy_test", "app_settings", None, {"targets": len(results)})
            status = "ok" if all(str(r.get("status")) == "OK" for r in results) else "warning"
            return redirect(url_for("admin_panel", msg=f"Proxy test completed ({status})."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Proxy test failed: {redact_proxy_credentials(str(e))}"))
        finally:
            db.close()

    @app.post("/admin/danger/wipe")
    @limiter.limit("5 per minute")
    def admin_danger_wipe():
        if not _admin_dangerous_ops_enabled():
            return redirect(url_for("admin_panel", msg="Dangerous operations are disabled."))
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
    @limiter.limit("20 per minute")
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
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} added."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Add feed failed: {e}"))
        finally:
            db.close()

    @app.get("/admin/feed/<source_id>/configure")
    @limiter.limit("30 per minute")
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

        fields_html = "".join(
            [
                (
                    f"<p><label>{_esc(str(f['label']))} "
                    + (
                        f"<input type='checkbox' name='{_esc(str(f.get('input_name') or ''))}' value='1' {'checked' if f.get('checked') else ''}/>"
                        if str(f.get("type") or "") == "checkbox"
                        else (
                            f"<input type='{'password' if f.get('secret') else 'text'}' "
                            f"name='{_esc(str(f.get('input_name') or ''))}' "
                            f"value='{_esc(str(f.get('value') or ''))}' "
                            f"placeholder='{_esc(str(f.get('placeholder') or ''))}'/>"
                        )
                    )
                    + "</label>"
                    + (f" Current: {_esc(str(f.get('current_masked') or ''))}" if f.get("secret") else "")
                    + "</p>"
                )
                for f in state["fields"]
            ]
        )
        orgs_html = ""
        if state.get("source_type") == "mwdb":
            if mwdb_orgs:
                options = "".join(
                    [
                        (
                            f"<label style='display:block'>"
                            f"<input type='checkbox' name='mwdb_orgs' value='{_esc(str(o.get('id') or o.get('name') or ''))}' "
                            f"{'checked' if str(o.get('id') or o.get('name') or '') in mwdb_selected_orgs else ''}/> "
                            f"{_esc(str(o.get('name') or o.get('id') or ''))}</label>"
                        )
                        for o in mwdb_orgs
                    ]
                )
                group_options = "<option value=''>(none — use TLP:GREEN for all)</option>" + "".join(
                    f"<option value='{_esc(str(o.get('id') or o.get('name') or ''))}'"
                    f"{' selected' if str(o.get('id') or o.get('name') or '') == mwdb_selected_group else ''}>"
                    f"{_esc(str(o.get('name') or o.get('id') or ''))}</option>"
                    for o in mwdb_orgs
                )
                orgs_html = (
                    f"<fieldset><legend>MWDB organizations</legend>{options}</fieldset>"
                    f"<fieldset><legend>My MWDB group (TLP:AMBER for group-visible indicators)</legend>"
                    f"<p style='margin:.2rem 0 .5rem'>Indicators uploaded by this group will be tagged <strong>TLP:AMBER</strong>.</p>"
                    f"<select name='mwdb_my_group'>{group_options}</select>"
                    f"</fieldset>"
                )
            else:
                orgs_html = "<p>MWDB organizations list is unavailable. Use <strong>Test connection</strong> first.</p>"
        return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1'/>
<title>Configure { _esc(source_id) }</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }}
  body[data-theme="light"] {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
  body[data-theme="dark"] {{ --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }}
  body:not([data-theme]) {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
  .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }}
  .topbar nav a {{ margin-right:.8rem; }}
  .card {{ border:1px solid var(--line); border-radius:12px; padding:1rem; background:var(--card); }}
  input, button {{ border:1px solid var(--line); border-radius:8px; padding:.4rem .5rem; background:var(--bg); color:var(--fg); }}
  fieldset {{ border:1px solid var(--line); border-radius:10px; margin:.8rem 0; padding:.6rem; }}
</style>
</head>
<body>
<header class="topbar" id="globalTopbar">
  <nav>
    <a href="/">Overview</a>
    <a href="/indicators">Indicators</a>
    <a href="/admin">Admin</a>
    <a href="/logs">Logs</a>
  </nav>
  <button type="button" id="themeToggleGlobal">Toggle dark mode</button>
</header>
<div class='card'>
<h1>Configure feed: {_esc(source_id)}</h1>
<p>{_esc(msg)}</p>
<p>Status: {'OK' if state['ready'] else 'Incomplete: ' + _esc(', '.join(state['missing']))}</p>
<form method='post' action='/admin/feed/{_esc(source_id)}/configure' id='feedConfigForm'>
<p><label>Display name <input type='text' name='display_name' value='{_esc(feed.display_name)}' required/></label></p>
<p><label>Schedule cron <input type='text' name='schedule_cron' value='{_esc(feed.schedule_cron)}'/></label></p>
{fields_html}
{orgs_html}
<button type='submit' id='saveBtn'>Save settings</button>
<button type='submit' formaction='/admin/feed/{_esc(source_id)}/test' formmethod='post' id='testBtn'>Test connection</button>
<a href='/admin'>Back</a>
</form>
</div>
<script>
const themeKey = 'ioc-theme';
const preferredTheme = localStorage.getItem(themeKey);
if (preferredTheme === 'dark' || preferredTheme === 'light') {{
  document.body.setAttribute('data-theme', preferredTheme);
}} else {{
  const systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  document.body.setAttribute('data-theme', systemDark ? 'dark' : 'light');
}}
const themeToggle = document.getElementById('themeToggleGlobal');
if (themeToggle) {{
  themeToggle.addEventListener('click', () => {{
    const curr = document.body.getAttribute('data-theme') || 'light';
    const next = curr === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', next);
    localStorage.setItem(themeKey, next);
  }});
}}
const form = document.getElementById('feedConfigForm');
if (form) {{
  form.addEventListener('submit', function (evt) {{
    const submitter = evt.submitter;
    const saveBtn = document.getElementById('saveBtn');
    const testBtn = document.getElementById('testBtn');
    if (saveBtn) saveBtn.disabled = true;
    if (testBtn) testBtn.disabled = true;
    if (submitter && submitter.id === 'testBtn') {{
      submitter.textContent = 'Testing...';
    }} else if (saveBtn) {{
      saveBtn.textContent = 'Saving...';
    }}
  }});
}}
</script>
</body></html>"""

    @app.post("/admin/feed/<source_id>/configure")
    @limiter.limit("20 per minute")
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
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} configuration saved."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Configure feed failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed/<source_id>/test")
    @limiter.limit("20 per minute")
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
            return redirect(url_for("admin_feed_configure", source_id=source_id, msg=f"Connection test {status}: {msg}"))
        except Exception as e:
            return redirect(url_for("admin_feed_configure", source_id=source_id, msg=f"Connection test failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed-toggle")
    @limiter.limit("20 per minute")
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
            _audit("admin_feed_toggle", "feed", None, {"source": source_name, "enabled": enabled})
            return redirect(url_for("admin_panel", msg=f"Feed {source_name} {'enabled' if enabled else 'disabled'}"))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Feed toggle failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/feed/<source_id>/delete")
    @limiter.limit("20 per minute")
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
            return redirect(url_for("admin_panel", msg=f"Feed {source_id} deleted (soft)."))
        except Exception as e:
            db.rollback()
            return redirect(url_for("admin_panel", msg=f"Delete feed failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/sync")
    @limiter.limit("10 per minute")
    def admin_sync():
        source_name = (request.form.get("source") or "").strip().lower()
        if not source_name:
            return redirect(url_for("admin_panel", msg="Missing source for sync."))
        db = _db()
        try:
            _app_log("INFO", "scheduler", "manual_sync_requested", metadata={"source": source_name}, db=db)
            _ensure_default_feeds(db)
            feed_rows = _read_feed_rows(db)
            feed_map = {f.source_id: f for f in feed_rows}
            targets: List[Feed] = []
            if source_name == "all":
                targets = [f for f in feed_rows if f.enabled]
            elif source_name not in feed_map:
                return redirect(url_for("admin_panel", msg="Invalid source for sync."))
            else:
                targets = [feed_map[source_name]]

            blocked: List[str] = []
            queued: List[str] = []
            reused: List[str] = []
            for feed in targets:
                state = _read_feed_config_state(db, feed)
                if not state["ready"]:
                    blocked.append(f"{feed.source_id} (missing: {', '.join(state['missing'])})")
                    continue
                job, created = _enqueue_sync_job(feed, trigger_type="manual", db=db)
                if created:
                    queued.append(job.job_id)
                else:
                    reused.append(job.job_id)

            if source_name != "all" and not queued and not reused:
                return redirect(url_for("admin_panel", msg=f"Cannot sync {source_name}: configuration incomplete."))

            _audit("manual_sync", "feed", None, {"source": source_name, "queued": queued, "reused": reused, "blocked": blocked})
            _app_log("INFO", "scheduler", "manual_sync_queued", metadata={"source": source_name, "queued": queued, "reused": reused, "blocked": blocked}, db=db)
            msg = f"Sync queued for {source_name}."
            if queued:
                msg += f" New jobs: {', '.join(queued)}."
            if reused:
                msg += f" Already queued/running: {', '.join(reused)}."
            if blocked:
                msg += f" Skipped incomplete feeds: {', '.join(blocked)}."
            return redirect(url_for("admin_panel", msg=msg))
        except Exception as e:
            logger.exception("admin_sync_failed")
            _app_log("ERROR", "scheduler", "manual_sync_failed", metadata={"source": source_name, "error": str(e)}, db=db)
            return redirect(url_for("admin_panel", msg=f"Sync failed: {e}"))
        finally:
            db.close()

    @app.get("/admin/sync-jobs/<job_id>")
    @limiter.limit("30 per minute")
    def admin_sync_job_details(job_id: str):
        job_id = (job_id or "").strip()
        if not job_id:
            return redirect(url_for("admin_panel", msg="Missing job_id."))
        db = _db(read_only=True)
        try:
            job = db.scalar(select(SyncJob).where(SyncJob.job_id == job_id))
            if not job:
                return redirect(url_for("admin_panel", msg=f"Sync job not found: {job_id}"))
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == job_id))
            logs = list(db.scalars(select(AppLog).where(AppLog.run_id == job_id).order_by(AppLog.created_at.desc()).limit(200)).all())
        finally:
            db.close()

        log_rows = "".join(
            [
                (
                    "<tr>"
                    f"<td>{_esc(str(item.created_at))}</td>"
                    f"<td>{_esc(item.level)}</td>"
                    f"<td>{_esc(item.component)}</td>"
                    f"<td>{_esc(item.message)}</td>"
                    f"<td><code>{_esc(json.dumps(item.metadata_ or {}, ensure_ascii=True))}</code></td>"
                    "</tr>"
                )
                for item in logs
            ]
        ) or "<tr><td colspan='5'>No logs for this job.</td></tr>"

        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Sync Job { _esc(job_id) }</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }}
  body[data-theme="light"] {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
  body[data-theme="dark"] {{ --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }}
  body:not([data-theme]) {{ --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }}
  .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }}
  .card {{ border: 1px solid var(--line); border-radius: 12px; padding: 1rem; margin-bottom: 1rem; background: var(--card); }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ border-bottom:1px solid var(--line); padding:.45rem; text-align:left; vertical-align:top; }}
  button {{ padding: .5rem .8rem; border-radius: 8px; border: 1px solid var(--line); background: var(--card); color: var(--fg); }}
</style>
</head>
<body>
  <header class="topbar" id="globalTopbar">
    <nav>
      <a href="/">Overview</a>
      <a href="/indicators">Indicators</a>
      <a href="/admin">Admin</a>
      <a href="/logs">Logs</a>
    </nav>
    <button type="button" id="themeToggleGlobal">Toggle dark mode</button>
  </header>
  <div class="card">
    <h1>Sync Job Details</h1>
    <p><strong>Job ID:</strong> <code>{_esc(job.job_id)}</code></p>
    <p><strong>Source:</strong> {_esc(job.feed_source_id)} | <strong>Trigger:</strong> {_esc(job.trigger_type)} | <strong>Status:</strong> {_esc(job.status)}</p>
    <p><strong>Created:</strong> {_esc(str(job.created_at or ''))} | <strong>Started:</strong> {_esc(str(job.started_at or ''))} | <strong>Finished:</strong> {_esc(str(job.finished_at or ''))}</p>
    <p><strong>Error:</strong> {_esc(str(job.error or ''))}</p>
    <p><strong>Result:</strong> <code>{_esc(json.dumps(job.result_json or {}, ensure_ascii=True))}</code></p>
    <p><strong>FeedRun status:</strong> {_esc(str(getattr(run, 'status', 'n/a')))} | <strong>Fetched:</strong> {_esc(str(getattr(run, 'fetched_count', 'n/a')))}</p>
    <p><a href="/api/logs?job_id={_esc(job.job_id)}&limit=200">Open JSON logs for this job</a></p>
  </div>
  <div class="card">
    <h2>Job Logs</h2>
    <table>
      <thead><tr><th>Time</th><th>Level</th><th>Component</th><th>Message</th><th>Metadata</th></tr></thead>
      <tbody>{log_rows}</tbody>
    </table>
  </div>
  <script>
    const themeKey = 'ioc-theme';
    const preferredTheme = localStorage.getItem(themeKey);
    if (preferredTheme === 'dark' || preferredTheme === 'light') {{
      document.body.setAttribute('data-theme', preferredTheme);
    }}
    const themeToggle = document.getElementById('themeToggleGlobal');
    if (themeToggle) {{
      themeToggle.addEventListener('click', () => {{
        const curr = document.body.getAttribute('data-theme') || 'light';
        const next = curr === 'dark' ? 'light' : 'dark';
        document.body.setAttribute('data-theme', next);
        localStorage.setItem(themeKey, next);
      }});
    }}
  </script>
</body></html>"""

    @app.post("/admin/sync-jobs/<job_id>/retry")
    @limiter.limit("20 per minute")
    def admin_sync_job_retry(job_id: str):
        job_id = (job_id or "").strip()
        db = _db()
        try:
            job = db.scalar(select(SyncJob).where(SyncJob.job_id == job_id))
            if not job:
                return redirect(url_for("admin_panel", msg=f"Retry failed: job not found ({job_id})."))
            if str(job.status or "").lower() not in {"failed", "cancelled"}:
                return redirect(url_for("admin_panel", msg=f"Retry allowed only for failed/cancelled jobs (current: {job.status})."))
            feed = db.scalar(select(Feed).where(Feed.source_id == job.feed_source_id, Feed.deleted == False))  # noqa: E712
            if not feed:
                return redirect(url_for("admin_panel", msg=f"Retry failed: feed not found ({job.feed_source_id})."))
            state = _read_feed_config_state(db, feed)
            if not state["ready"]:
                return redirect(url_for("admin_panel", msg=f"Retry blocked: configuration incomplete for {feed.source_id}."))
            new_job, created = _enqueue_sync_job(feed, trigger_type="retry", db=db)
            return redirect(url_for("admin_panel", msg=f"Retry {'queued' if created else 'reused existing'} for {feed.source_id} (job_id={new_job.job_id})."))
        except Exception as e:
            logger.exception("admin_sync_job_retry_failed")
            return redirect(url_for("admin_panel", msg=f"Retry failed: {e}"))
        finally:
            db.close()

    @app.post("/admin/sync-jobs/<job_id>/cancel")
    @limiter.limit("20 per minute")
    def admin_sync_job_cancel(job_id: str):
        job_id = (job_id or "").strip()
        db = _db()
        try:
            job = db.scalar(select(SyncJob).where(SyncJob.job_id == job_id))
            if not job:
                return redirect(url_for("admin_panel", msg=f"Cancel failed: job not found ({job_id})."))
            status = str(job.status or "").lower()
            if status in {"success", "failed", "cancelled"}:
                return redirect(url_for("admin_panel", msg=f"Cancel ignored: job already {status}."))
            now = datetime.now(timezone.utc)
            run = db.scalar(select(FeedRun).where(FeedRun.run_id == job.job_id))
            if status == "queued":
                job.status = "cancelled"
                job.error = "cancelled by admin"
                job.finished_at = now
                job.result_json = {"cancelled": True}
                if run:
                    run.status = "cancelled"
                    run.error = "cancelled by admin"
                    run.finished_at = now
                db.commit()
                return redirect(url_for("admin_panel", msg=f"Job {job.job_id} cancelled."))
            job.status = "cancel_requested"
            if not job.error:
                job.error = "cancel requested by admin"
            if run and run.status == "running":
                run.error = "cancel requested by admin"
            db.commit()
            return redirect(url_for("admin_panel", msg=f"Cancellation requested for running job {job.job_id}."))
        except Exception as e:
            db.rollback()
            logger.exception("admin_sync_job_cancel_failed")
            return redirect(url_for("admin_panel", msg=f"Cancel failed: {e}"))
        finally:
            db.close()

    @app.post("/api/sync")
    @limiter.limit("20 per minute")
    def api_sync():
        payload = request.get_json(silent=True) or {}
        source_name = str(payload.get("source") or request.args.get("source") or "").strip().lower()
        if not source_name:
            return jsonify({"error": "Missing source"}), 400
        db = _db()
        try:
            _ensure_default_feeds(db)
            feed_rows = _read_feed_rows(db)
            feed_map = {f.source_id: f for f in feed_rows}
            if source_name == "all":
                targets = [f for f in feed_rows if f.enabled]
            elif source_name in feed_map:
                targets = [feed_map[source_name]]
            else:
                return jsonify({"error": "Invalid source"}), 400

            blocked: List[str] = []
            queued: List[Dict[str, Any]] = []
            for feed in targets:
                state = _read_feed_config_state(db, feed)
                if not state["ready"]:
                    blocked.append(feed.source_id)
                    continue
                job, created = _enqueue_sync_job(feed, trigger_type="manual", db=db)
                queued.append({"feed_source_id": feed.source_id, "job_id": job.job_id, "created": created})

            if source_name != "all" and not queued:
                return jsonify({"error": "Configuration incomplete", "source": source_name, "blocked": blocked}), 400
            return jsonify({"source": source_name, "jobs": queued, "blocked": blocked}), 202
        finally:
            db.close()

    @app.get("/api/feeds")
    @limiter.limit("60 per minute")
    def api_feeds():
        def _int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(request.args.get(name, str(default)))
            except ValueError:
                value = default
            return max(minimum, min(maximum, value))

        limit = _int_arg("limit", 25, 1, 100)
        offset = _int_arg("offset", 0, 0, 1000000)
        sort_by = (request.args.get("sort", "source") or "source").strip().lower()
        sort_order = (request.args.get("order", "asc") or "asc").strip().lower()
        status_filter = (request.args.get("status", "all") or "all").strip().upper()
        datasource = (request.args.get("datasource", "all") or "all").strip().lower()
        configured = (request.args.get("configured", "all") or "all").strip().lower()
        query_text = (request.args.get("q", "") or "").strip()
        problems_only = (request.args.get("problems_only", "0") or "0").strip().lower() in {"1", "true", "yes", "on"}

        db = _db(read_only=True)
        try:
            all_items = _build_feed_items(db)
            filtered = _apply_feed_filters_and_sort(
                all_items,
                status_filter=status_filter,
                datasource=datasource,
                configured=configured,
                query_text=query_text,
                problems_only=problems_only,
                sort_by=sort_by,
                sort_order=sort_order,
            )
            total = len(filtered)
            if offset >= total and total > 0:
                offset = max(0, ((total - 1) // max(1, limit)) * max(1, limit))
            page = filtered[offset : offset + limit]
            return jsonify(
                {
                    "items": [
                        {
                            **item,
                            "last_run_at": item["last_run_at"].isoformat() if isinstance(item.get("last_run_at"), datetime) else None,
                            "last_error_at": item["last_error_at"].isoformat() if isinstance(item.get("last_error_at"), datetime) else None,
                        }
                        for item in page
                    ],
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "sort": sort_by,
                    "order": sort_order,
                    "filters": {
                        "status": status_filter,
                        "datasource": datasource,
                        "configured": configured,
                        "q": query_text,
                        "problems_only": problems_only,
                    },
                }
            )
        finally:
            db.close()

    @app.get("/api/feeds/metrics")
    @limiter.limit("60 per minute")
    def api_feeds_metrics():
        hours, window = _resolve_metrics_window_hours()
        datasource = (request.args.get("datasource") or "all").strip().lower()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        bucket_granularity = "hour" if hours <= 24 else "day"

        db = _db(read_only=True)
        try:
            feed_items = _build_feed_items(db)
            if datasource not in {"", "all"}:
                feed_items = [item for item in feed_items if str(item.get("source_type", "")).lower() == datasource]

            source_ids = [str(item["source_id"]) for item in feed_items]
            if not source_ids:
                return jsonify({"window": window, "hours": hours, "bucket": bucket_granularity, "datasource": datasource, "total_feeds": 0, "items": [], "timeseries": [], "summary": {}})

            runs = list(
                db.scalars(
                    select(FeedRun)
                    .where(FeedRun.feed_source_id.in_(source_ids), FeedRun.started_at >= cutoff)
                    .order_by(FeedRun.feed_source_id.asc(), FeedRun.started_at.asc())
                ).all()
            )
            by_feed: Dict[str, List[FeedRun]] = {sid: [] for sid in source_ids}
            for run in runs:
                by_feed.setdefault(str(run.feed_source_id), []).append(run)

            metric_items: List[Dict[str, Any]] = []
            aggregate_runs = 0
            aggregate_success = 0
            aggregate_errors = 0
            aggregate_fetched = 0
            aggregate_duration_total_ms = 0
            aggregate_duration_count = 0
            all_durations: List[int] = []
            all_buckets: Dict[str, Dict[str, Any]] = {}

            def _bucket_key(ts: datetime) -> str:
                if bucket_granularity == "hour":
                    return ts.replace(minute=0, second=0, microsecond=0).isoformat()
                return ts.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

            for item in feed_items:
                sid = str(item["source_id"])
                feed_runs = by_feed.get(sid, [])
                total_runs = len(feed_runs)
                success_runs = 0
                error_runs = 0
                total_fetched = 0
                duration_ms_total = 0
                duration_ms_count = 0
                durations: List[int] = []
                run_points: List[Dict[str, Any]] = []
                for run in feed_runs:
                    status = str(run.status or "").lower()
                    if status == "success":
                        success_runs += 1
                    if status in {"failed", "cancelled"}:
                        error_runs += 1
                    total_fetched += int(run.fetched_count or 0)
                    duration_ms = None
                    if run.finished_at is not None and run.started_at is not None:
                        duration_ms = max(0, int((run.finished_at - run.started_at).total_seconds() * 1000))
                        duration_ms_total += duration_ms
                        duration_ms_count += 1
                        durations.append(duration_ms)
                        all_durations.append(duration_ms)
                    if run.started_at is not None:
                        bk = _bucket_key(run.started_at)
                        point = all_buckets.setdefault(
                            bk,
                            {"ts": bk, "runs": 0, "success_runs": 0, "error_runs": 0, "fetched_total": 0, "duration_ms_total": 0, "duration_ms_count": 0},
                        )
                        point["runs"] += 1
                        if status == "success":
                            point["success_runs"] += 1
                        if status in {"failed", "cancelled"}:
                            point["error_runs"] += 1
                        point["fetched_total"] += int(run.fetched_count or 0)
                        if duration_ms is not None:
                            point["duration_ms_total"] += int(duration_ms)
                            point["duration_ms_count"] += 1
                    run_points.append(
                        {
                            "run_id": run.run_id,
                            "status": run.status,
                            "started_at": run.started_at.isoformat() if run.started_at else None,
                            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                            "fetched_count": int(run.fetched_count or 0),
                            "duration_ms": duration_ms,
                            "details_url": f"/admin/sync-jobs/{run.run_id}",
                            "logs_url": f"/api/logs?run_id={run.run_id}&limit=200",
                        }
                    )
                availability = round((success_runs / total_runs) * 100, 2) if total_runs else None
                error_rate = round((error_runs / total_runs) * 100, 2) if total_runs else None
                avg_duration_ms = round(duration_ms_total / duration_ms_count, 2) if duration_ms_count else None
                avg_fetched = round(total_fetched / total_runs, 2) if total_runs else None

                aggregate_runs += total_runs
                aggregate_success += success_runs
                aggregate_errors += error_runs
                aggregate_fetched += total_fetched
                aggregate_duration_total_ms += duration_ms_total
                aggregate_duration_count += duration_ms_count

                metric_items.append(
                    {
                        "source_id": sid,
                        "display_name": item["display_name"],
                        "source_type": item["source_type"],
                        "status": item["status"],
                        "runs": total_runs,
                        "success_runs": success_runs,
                        "error_runs": error_runs,
                        "availability_pct": availability,
                        "error_rate_pct": error_rate,
                        "fetched_total": total_fetched,
                        "fetched_avg_per_run": avg_fetched,
                        "duration_avg_ms": avg_duration_ms,
                        "duration_p50_ms": _percentile(durations, 50.0),
                        "duration_p95_ms": _percentile(durations, 95.0),
                        "window_hours": hours,
                        "runs_timeseries": run_points[-200:],
                    }
                )

            timeseries = []
            for ts in sorted(all_buckets.keys()):
                bucket = all_buckets[ts]
                timeseries.append(
                    {
                        "ts": ts,
                        "runs": int(bucket["runs"]),
                        "success_runs": int(bucket["success_runs"]),
                        "error_runs": int(bucket["error_runs"]),
                        "fetched_total": int(bucket["fetched_total"]),
                        "duration_avg_ms": (round(float(bucket["duration_ms_total"]) / float(bucket["duration_ms_count"]), 2) if int(bucket["duration_ms_count"]) > 0 else None),
                    }
                )

            summary = {
                "runs_total": aggregate_runs,
                "availability_pct": round((aggregate_success / aggregate_runs) * 100, 2) if aggregate_runs else None,
                "error_rate_pct": round((aggregate_errors / aggregate_runs) * 100, 2) if aggregate_runs else None,
                "fetched_total": aggregate_fetched,
                "fetched_avg_per_run": round((aggregate_fetched / aggregate_runs), 2) if aggregate_runs else None,
                "duration_avg_ms": round((aggregate_duration_total_ms / aggregate_duration_count), 2) if aggregate_duration_count else None,
                "duration_p50_ms": _percentile(all_durations, 50.0),
                "duration_p95_ms": _percentile(all_durations, 95.0),
            }
            return jsonify({"window": window, "hours": hours, "bucket": bucket_granularity, "datasource": datasource, "total_feeds": len(metric_items), "items": metric_items, "timeseries": timeseries, "summary": summary})
        finally:
            db.close()

    @app.get("/api/logs")
    @limiter.limit("60 per minute")
    def api_logs():
        db = _db(read_only=True)
        try:
            stmt = select(AppLog).order_by(AppLog.created_at.desc())
            feed = (request.args.get("feed") or "").strip()
            job_id = (request.args.get("job_id") or request.args.get("run_id") or "").strip()
            level = (request.args.get("level") or "").strip().upper()
            component = (request.args.get("component") or "").strip()
            since = (request.args.get("since") or "").strip()
            until = (request.args.get("until") or "").strip()
            if feed:
                stmt = stmt.where(AppLog.feed_source_id == feed)
            if job_id:
                stmt = stmt.where(AppLog.run_id == job_id)
            if level:
                stmt = stmt.where(AppLog.level == level)
            if component:
                stmt = stmt.where(AppLog.component == component)
            if since:
                try:
                    stmt = stmt.where(AppLog.created_at >= datetime.fromisoformat(since.replace("Z", "+00:00")))
                except ValueError:
                    pass
            if until:
                try:
                    stmt = stmt.where(AppLog.created_at <= datetime.fromisoformat(until.replace("Z", "+00:00")))
                except ValueError:
                    pass
            limit = min(500, max(1, int(request.args.get("limit", "200"))))
            rows = list(db.scalars(stmt.limit(limit)).all())
            return jsonify(
                {
                    "count": len(rows),
                    "items": [
                        {
                            "created_at": str(r.created_at),
                            "level": r.level,
                            "component": r.component,
                            "message": r.message,
                            "feed_source_id": r.feed_source_id,
                            "run_id": r.run_id,
                            "metadata": r.metadata_,
                        }
                        for r in rows
                    ],
                }
            )
        finally:
            db.close()

    @app.get("/api/runs/current")
    @limiter.limit("60 per minute")
    def api_runs_current():
        db = _db(read_only=True)
        try:
            running = list(db.scalars(select(FeedRun).where(FeedRun.status == "running").order_by(FeedRun.started_at.desc()).limit(20)).all())
            latest = list(db.scalars(select(FeedRun).order_by(FeedRun.started_at.desc()).limit(20)).all())
            queued_jobs = list(db.scalars(select(SyncJob).where(SyncJob.status.in_(["queued", "running"])).order_by(SyncJob.created_at.asc()).limit(50)).all())
            heartbeat = _get_setting(db, "scheduler.heartbeat", "")
            return jsonify(
                {
                    "scheduler_heartbeat": heartbeat,
                    "active_run_id": scheduler_state.get("active_run_id"),
                    "active_job_id": scheduler_state.get("active_job_id"),
                    "queued_jobs": [
                        {
                            "job_id": j.job_id,
                            "feed_source_id": j.feed_source_id,
                            "status": j.status,
                            "trigger_type": j.trigger_type,
                            "created_at": str(j.created_at),
                            "started_at": str(j.started_at),
                        }
                        for j in queued_jobs
                    ],
                    "running": [{"feed_source_id": r.feed_source_id, "run_id": r.run_id, "status": r.status, "started_at": str(r.started_at)} for r in running],
                    "latest": [
                        {
                            "feed_source_id": r.feed_source_id,
                            "run_id": r.run_id,
                            "status": r.status,
                            "started_at": str(r.started_at),
                            "finished_at": str(r.finished_at),
                            "error": r.error,
                            "fetched_count": r.fetched_count,
                        }
                        for r in latest
                    ],
                }
            )
        finally:
            db.close()

    @app.get("/logs")
    @limiter.limit("30 per minute")
    def logs_page():
        return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><title>Logs</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0 1.5rem 1.5rem; background: var(--bg); color: var(--fg); }
  body[data-theme="light"] { --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }
  body[data-theme="dark"] { --bg: #0f172a; --fg: #e2e8f0; --card: #111827; --line: #334155; }
  body:not([data-theme]) { --bg: #f8fafc; --fg: #0f172a; --card: #ffffff; --line: #dbe1ea; }
  .topbar { display:flex; justify-content:space-between; align-items:center; gap:1rem; padding:.8rem 0; margin-bottom:1rem; border-bottom:1px solid var(--line); }
  .topbar nav a { margin-right:.8rem; }
  .card { border:1px solid var(--line); border-radius:12px; padding:1rem; background:var(--card); }
  input, button { border:1px solid var(--line); border-radius:8px; padding:.4rem .5rem; background:var(--bg); color:var(--fg); }
  label { display:inline-block; margin: .2rem .6rem .2rem 0; }
  pre { white-space: pre-wrap; border:1px solid var(--line); padding:10px; min-height:300px; background:var(--card); }
</style></head><body>
<header class="topbar" id="globalTopbar">
  <nav>
    <a href="/">Overview</a>
    <a href="/indicators">Indicators</a>
    <a href="/admin">Admin</a>
    <a href="/logs">Logs</a>
  </nav>
  <button type="button" id="themeToggleGlobal">Toggle dark mode</button>
</header>
<div class="card">
<h1>Logs</h1><p><a href="/admin">Back to admin</a></p>
<form id="filters">
  <label>Feed <input name="feed" /></label>
  <label>Job ID <input name="job_id" /></label>
  <label>Level <input name="level" placeholder="INFO|WARN|ERROR" /></label>
  <label>Component <input name="component" placeholder="scheduler|fetcher|parser|exporter" /></label>
  <label>Since <input name="since" placeholder="2026-02-26T00:00:00Z" /></label>
  <label>Until <input name="until" placeholder="2026-02-26T23:59:59Z" /></label>
  <label><input type="checkbox" id="autorefresh" checked/> auto-refresh</label>
  <button type="submit">Apply</button>
  <button type="button" id="copyBtn">Copy all visible logs</button>
  <button type="button" id="downloadBtn">Download visible .log</button>
</form>
<p id="copyStatus" role="status" aria-live="polite"></p>
<pre id="out"></pre>
</div>
<script>
const themeKey = 'ioc-theme';
const preferredTheme = localStorage.getItem(themeKey);
if (preferredTheme === 'dark' || preferredTheme === 'light') {
  document.body.setAttribute('data-theme', preferredTheme);
} else {
  const systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  document.body.setAttribute('data-theme', systemDark ? 'dark' : 'light');
}
const themeToggle = document.getElementById('themeToggleGlobal');
if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const curr = document.body.getAttribute('data-theme') || 'light';
    const next = curr === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', next);
    localStorage.setItem(themeKey, next);
  });
}
let visibleRows = [];
function setCopyStatus(message, kind){
  const el = document.getElementById('copyStatus');
  if (!el) return;
  el.textContent = message || '';
  el.style.color = kind === 'error' ? '#b91c1c' : '#047857';
}
function buildQuery(){const fd=new FormData(document.getElementById('filters'));const p=new URLSearchParams();for(const [k,v] of fd.entries()){if((v||'').trim())p.set(k,v);}p.set('limit','200');return p.toString();}
function formatLine(x){return `[${x.created_at}] ${x.level} ${x.component} ${x.feed_source_id||'-'} ${x.run_id||'-'} ${x.message} ${JSON.stringify(x.metadata||{})}`;}
function buildVisibleText(){
  const lines = (visibleRows || []).map(formatLine);
  return lines.join('\\n');
}
function fallbackCopyText(payload){
  const ta = document.createElement('textarea');
  ta.value = payload;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '-9999px';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
  document.body.removeChild(ta);
  return ok;
}
async function copyVisibleLogs(){
  const payload = buildVisibleText();
  const lineCount = payload ? payload.split('\\n').length : 0;
  if (!payload) {
    setCopyStatus('No visible logs to copy.', 'error');
    return;
  }
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(payload);
      setCopyStatus(`Copied ${lineCount} lines.`, 'ok');
      return;
    }
  } catch (err) {
  }
  const copied = fallbackCopyText(payload);
  if (copied) {
    setCopyStatus(`Copied ${lineCount} lines (fallback).`, 'ok');
  } else {
    setCopyStatus('Copy failed. Use HTTPS/focused tab or copy manually.', 'error');
  }
}
function downloadVisibleLogs(){
  const payload = buildVisibleText();
  if (!payload) {
    setCopyStatus('No visible logs to download.', 'error');
    return;
  }
  const blob = new Blob([payload + '\\n'], {type: 'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const ts = new Date().toISOString().replace(/[:]/g, '-');
  a.href = url;
  a.download = `visible-logs-${ts}.log`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  setCopyStatus(`Downloaded ${(visibleRows || []).length} lines.`, 'ok');
}
async function refreshLogs(){
  const q=buildQuery();
  try {
    const r=await fetch('/api/logs?'+q);
    const d=await r.json();
    visibleRows = d.items || [];
    const lines=visibleRows.map(formatLine);
    document.getElementById('out').textContent=lines.length ? lines.join('\\n') : 'No logs found for current filters.';
  } catch (err) {
    visibleRows = [];
    document.getElementById('out').textContent='Failed to load logs.';
    setCopyStatus('Failed to refresh logs.', 'error');
  }
}
document.getElementById('filters').addEventListener('submit',(e)=>{e.preventDefault();refreshLogs();});
document.getElementById('copyBtn').addEventListener('click',copyVisibleLogs);
document.getElementById('downloadBtn').addEventListener('click',downloadVisibleLogs);
setInterval(()=>{if(document.getElementById('autorefresh').checked)refreshLogs();},5000);refreshLogs();
</script></body></html>"""
