"""
feed_config_svc — feed source templates, configuration state, validation,
connection testing and proxy test helpers.

All functions are closures bound to the injected dependencies via
make_feed_config_service(). Nothing in this module imports from factory.py.
"""
from __future__ import annotations

import html
import re
import time
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Feed
from .common import build_feed_session, redact_proxy_credentials


def make_feed_config_service(*, cfg, get_setting_fn, set_setting_fn, secret_decrypt_fn):
    """Return a namespace of feed-configuration functions."""

    # ------------------------------------------------------------------ pure helpers

    def _field_input_name(setting_key: str) -> str:
        return setting_key.replace(".", "__")

    def _feed_value_key(source_id: str, key: str) -> str:
        return f"feedcfg.{source_id}.{key}"

    def _feed_secret_key(source_id: str, key: str) -> str:
        return f"feedsecret.{source_id}.{key}"

    def _is_valid_http_url(value: str) -> bool:
        v = (value or "").strip()
        try:
            from urllib.parse import urlparse
            parsed = urlparse(v)
            return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
        except Exception:
            return False

    def _is_valid_cron_field(expr: str, *, min_v: int, max_v: int) -> bool:
        expr = expr.strip()
        if expr == "*":
            return True
        if expr.startswith("*/"):
            try:
                step = int(expr[2:])
                return step > 0
            except ValueError:
                return False
        for part in expr.split(","):
            part = part.strip()
            try:
                n = int(part)
                if not (min_v <= n <= max_v):
                    return False
            except ValueError:
                return False
        return True

    def _extract_title_from_html(body: str) -> str:
        if not body:
            return ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
        if m:
            return html.unescape(re.sub(r"\s+", " ", m.group(1)).strip())[:200]
        m2 = re.search(
            r"<meta[^>]+property=[\"']og:title[\"'][^>]+content=[\"']([^\"']+)[\"'][^>]*>",
            body,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if m2:
            return html.unescape(re.sub(r"\s+", " ", m2.group(1)).strip())[:200]
        return ""

    def _proxy_test_expected_match(target_key: str, title: str) -> bool:
        t = (title or "").lower()
        if target_key == "mwdb":
            return ("mwdb" in t) or ("malware" in t)
        if target_key == "abusech":
            return "abuse.ch" in t
        if target_key == "certpl":
            return ("cert" in t) or ("cert.pl" in t)
        return True

    # ------------------------------------------------------------------ source templates

    def _source_templates() -> Dict[str, Dict[str, Any]]:
        return {
            "misp": {
                "display_name": "MISP",
                "fields": [
                    {"key": "base_url", "label": "MISP URL", "secret": False, "required": True, "env": "MISP_URL", "placeholder": "https://misp.example.local"},
                    {"key": "api_key", "label": "MISP API key", "secret": True, "required": True, "env": "MISP_API_KEY", "placeholder": "Leave blank to keep current"},
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "MISP_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                ],
            },
            "crowdsec": {
                "display_name": "CrowdSec",
                "fields": [
                    {"key": "api_key", "label": "CrowdSec API key", "secret": True, "required": True, "env": "CROWDSEC_API_KEY", "placeholder": "Leave blank to keep current"},
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "CROWDSEC_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                ],
            },
            "malwarebazaar": {
                "display_name": "MalwareBazaar",
                "fields": [
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "MALWAREBAZAAR_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                ],
            },
            "mwdb": {
                "display_name": "MWDB",
                "fields": [
                    {"key": "base_url", "label": "MWDB URL", "secret": False, "required": True, "env": "MWDB_URL", "placeholder": "https://mwdb.example.local"},
                    {"key": "api_key", "label": "MWDB auth key", "secret": True, "required": True, "env": "MWDB_AUTH_KEY", "placeholder": "Leave blank to keep current"},
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "MWDB_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                    {"key": "tags", "label": "MWDB tags (comma-separated)", "secret": False, "required": False, "env": "MWDB_TAGS", "placeholder": "apt, malware"},
                    {"key": "days", "label": "MWDB days", "secret": False, "required": False, "env": "MWDB_DAYS", "placeholder": "30"},
                    {"key": "no_time_limit", "label": "No time limit", "secret": False, "required": False, "env": "MWDB_NO_TIME_LIMIT", "type": "checkbox"},
                ],
            },
            "abusech": {
                "display_name": "abuse.ch",
                "fields": [
                    {"key": "api_key", "label": "abuse.ch auth key", "secret": True, "required": False, "env": "ABUSECH_AUTH_KEY", "placeholder": "Leave blank to keep current"},
                    {"key": "custom_filter", "label": "Custom filter", "secret": False, "required": False, "env": "ABUSECH_CUSTOM_FILTER", "placeholder": "Optional query filter"},
                    {"key": "threatfox_enabled", "label": "ThreatFox", "secret": False, "required": False, "env": "THREATFOX_ENABLED", "type": "checkbox"},
                    {"key": "urlhaus_enabled", "label": "URLhaus", "secret": False, "required": False, "env": "URLHAUS_ENABLED", "type": "checkbox"},
                    {"key": "feodotracker_enabled", "label": "FeodoTracker", "secret": False, "required": False, "env": "FEODOTRACKER_ENABLED", "type": "checkbox"},
                    {"key": "yaraify_enabled", "label": "YARAify", "secret": False, "required": False, "env": "YARAIFY_ENABLED", "type": "checkbox"},
                    {"key": "yaraify_auth_key", "label": "YARAify auth key", "secret": True, "required": False, "env": "YARAIFY_AUTH_KEY", "placeholder": "Leave blank to use abuse.ch auth key"},
                    {"key": "yaraify_identifier", "label": "YARAify identifier", "secret": False, "required": False, "env": "YARAIFY_IDENTIFIER", "placeholder": "Optional YARAify task identifier"},
                    {"key": "yaraify_lookup_hashes", "label": "YARAify lookup hashes", "secret": False, "required": False, "env": "YARAIFY_LOOKUP_HASHES", "placeholder": "Optional comma-separated hashes"},
                    {"key": "hunting_fplist_enabled", "label": "Hunting FPList", "secret": False, "required": False, "env": "HUNTING_FPLIST_ENABLED", "type": "checkbox"},
                    {"key": "hunting_auth_key", "label": "Hunting auth key", "secret": True, "required": False, "env": "HUNTING_AUTH_KEY", "placeholder": "Leave blank to use abuse.ch auth key"},
                    {"key": "hunting_fplist_format", "label": "Hunting FPList format", "secret": False, "required": False, "env": "HUNTING_FPLIST_FORMAT", "placeholder": "csv"},
                ],
            },
        }

    # ------------------------------------------------------------------ feed enable/default

    def _read_feed_enabled(db: Session, source_name: str) -> bool:
        raw = get_setting_fn(db, f"feed.{source_name}.enabled", "1")
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def _ensure_default_feeds(db: Session) -> None:
        existing = db.scalars(select(Feed).where(Feed.deleted == False)).all()  # noqa: E712
        if existing:
            return
        defaults = [
            ("misp", "misp", "MISP"),
            ("crowdsec", "crowdsec", "CrowdSec"),
            ("malwarebazaar", "malwarebazaar", "MalwareBazaar"),
            ("mwdb", "mwdb", "MWDB"),
            ("abusech", "abusech", "abuse.ch"),
        ]
        for source_id, source_type, display_name in defaults:
            db.add(
                Feed(
                    source_id=source_id,
                    source_type=source_type,
                    display_name=display_name,
                    schedule_cron="*/15 * * * *",
                    enabled=(source_id != "misp"),
                    deleted=False,
                )
            )
        db.commit()

    # ------------------------------------------------------------------ config state

    def _read_feed_config_state(db: Session, feed: Feed) -> Dict[str, Any]:
        defs = _source_templates().get(feed.source_type)
        if not defs:
            return {"source_id": feed.source_id, "ready": False, "missing": ["unknown source type"], "enabled": feed.enabled}
        missing: List[str] = []
        normalized_fields: List[Dict[str, Any]] = []
        for field_def in defs["fields"]:
            key = str(field_def["key"])
            if not key:
                continue
            required = bool(field_def.get("required", False))
            secret = bool(field_def.get("secret", False))
            input_type = str(field_def.get("type") or ("password" if secret else "text"))
            if key == "base_url":
                val = str(feed.base_url or "")
            else:
                setting_key = _feed_secret_key(feed.source_id, key) if secret else _feed_value_key(feed.source_id, key)
                val = get_setting_fn(db, setting_key, "", secret=secret)
            if required and not str(val).strip():
                missing.append(str(field_def.get("label") or key))
            normalized_fields.append(
                {
                    "key": key,
                    "label": str(field_def.get("label") or key),
                    "secret": secret,
                    "required": required,
                    "type": input_type,
                    "placeholder": str(field_def.get("placeholder") or ""),
                    "value": "" if secret else str(val),
                    "checked": (str(val).strip().lower() in {"1", "true", "yes", "on"}) if input_type == "checkbox" else False,
                    "current_masked": _mask_secret_fn(str(val)) if secret else "",
                    "input_name": _field_input_name(key),
                    "env": str(field_def.get("env") or ""),
                }
            )
        if feed.source_type == "malwarebazaar":
            shared_key = get_setting_fn(db, _feed_secret_key("abusech", "api_key"), "", secret=True)
            if not (shared_key or cfg.ABUSECH_AUTH_KEY):
                missing.append("abuse.ch auth key (ABUSECH_AUTH_KEY)")
        return {
            "source_id": feed.source_id,
            "source_type": feed.source_type,
            "display_name": feed.display_name,
            "ready": len(missing) == 0,
            "missing": missing,
            "enabled": bool(feed.enabled),
            "fields": normalized_fields,
        }

    def _mask_secret_fn(value: str) -> str:
        """Local copy so _read_feed_config_state doesn't need to import settings_svc."""
        if not value:
            return ""
        tail = value[-4:] if len(value) >= 4 else value
        return "*" * max(4, len(value) - len(tail)) + tail

    # ------------------------------------------------------------------ validation

    def _validate_feed_form(feed: Feed, form_data: Any, state: Dict[str, Any], db: Session) -> List[str]:
        errors: List[str] = []
        schedule_cron = (form_data.get("schedule_cron") or "*/15 * * * *").strip()
        cron_parts = schedule_cron.split()
        if len(cron_parts) != 5:
            errors.append("Invalid cron expression (expected 5 fields).")
        else:
            _cron_field_specs = [
                (cron_parts[0], 0, 59, "minute"),
                (cron_parts[1], 0, 23, "hour"),
                (cron_parts[2], 1, 31, "day"),
                (cron_parts[3], 1, 12, "month"),
                (cron_parts[4], 0, 7, "day-of-week"),
            ]
            bad = [name for expr, mn, mx, name in _cron_field_specs if not _is_valid_cron_field(expr, min_v=mn, max_v=mx)]
            if bad:
                errors.append(f"Invalid cron field(s): {', '.join(bad)}.")
        if feed.source_type in {"misp", "mwdb"}:
            base_url = (form_data.get("base_url") or "").strip()
            if not base_url:
                errors.append("Base URL is required.")
            elif not _is_valid_http_url(base_url):
                errors.append("Base URL must start with http:// or https://.")

        for f in state["fields"]:
            key = str(f["key"])
            input_name = str(f["input_name"])
            incoming = (form_data.get(input_name) or "").strip()
            if str(f.get("type") or "") == "checkbox":
                incoming = "1" if incoming.lower() in {"1", "true", "yes", "on"} else "0"
            if key in {"base_url"}:
                continue
            if bool(f.get("required")) and not incoming:
                current = get_setting_fn(
                    db,
                    _feed_secret_key(feed.source_id, key) if bool(f.get("secret")) else _feed_value_key(feed.source_id, key),
                    "",
                    secret=bool(f.get("secret")),
                )
                if not current:
                    errors.append(f"Missing required field: {f['label']}")

        if feed.source_type == "mwdb":
            days_raw = (form_data.get(_field_input_name("days")) or "").strip()
            no_limit = (form_data.get(_field_input_name("no_time_limit")) or "").strip().lower() in {"1", "true", "yes", "on"}
            if days_raw:
                try:
                    days_val = int(days_raw)
                    if days_val < 1 or days_val > 3650:
                        errors.append("MWDB days must be between 1 and 3650.")
                except ValueError:
                    errors.append("MWDB days must be an integer.")
            elif not no_limit:
                errors.append("Set MWDB days or enable No time limit.")

            tags_raw = (form_data.get(_field_input_name("tags")) or "").strip()
            if not tags_raw:
                errors.append("MWDB tags are required.")

        if feed.source_type == "abusech":
            toggles = {
                "threatfox_enabled": (form_data.get(_field_input_name("threatfox_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "urlhaus_enabled": (form_data.get(_field_input_name("urlhaus_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "feodotracker_enabled": (form_data.get(_field_input_name("feodotracker_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "yaraify_enabled": (form_data.get(_field_input_name("yaraify_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
                "hunting_fplist_enabled": (form_data.get(_field_input_name("hunting_fplist_enabled")) or "").strip().lower() in {"1", "true", "yes", "on"},
            }
            if not any(toggles.values()):
                errors.append("Select at least one abuse.ch service.")
            if toggles["yaraify_enabled"]:
                has_identifier = bool((form_data.get(_field_input_name("yaraify_identifier")) or "").strip())
                has_hashes = bool((form_data.get(_field_input_name("yaraify_lookup_hashes")) or "").strip())
                if not has_identifier and not has_hashes:
                    current_identifier = get_setting_fn(db, _feed_value_key(feed.source_id, "yaraify_identifier"), "", secret=False)
                    current_hashes = get_setting_fn(db, _feed_value_key(feed.source_id, "yaraify_lookup_hashes"), "", secret=False)
                    if not current_identifier and not current_hashes:
                        errors.append("YARAify requires an identifier or lookup hashes.")

        return errors

    # ------------------------------------------------------------------ connection testing

    def _fetch_mwdb_orgs(base_url: str, api_key: str) -> List[Dict[str, str]]:
        if not base_url or not api_key:
            return []
        from ..services.mwdb import fetch_mwdb_organizations
        try:
            return fetch_mwdb_organizations(base_url=base_url, auth_key=api_key, timeout_s=10)
        except Exception:
            return []

    def _get_feed_field_value(
        db: Session,
        feed: Feed,
        field: Dict[str, Any],
        form_data: Any | None = None,
    ) -> str:
        key = str(field.get("key") or "")
        input_name = str(field.get("input_name") or "")
        input_type = str(field.get("type") or "text")
        secret = bool(field.get("secret"))
        if key == "base_url":
            incoming = (form_data.get("base_url") if form_data is not None else None) or ""
            val = str(incoming).strip() or str(feed.base_url or "")
            return val
        stored = get_setting_fn(
            db,
            _feed_secret_key(feed.source_id, key) if secret else _feed_value_key(feed.source_id, key),
            "",
            secret=secret,
        )
        if form_data is None:
            return str(stored or "")
        if input_type == "checkbox":
            return "1" if str(form_data.get(input_name) or "").strip().lower() in {"1", "true", "yes", "on"} else "0"
        incoming = str(form_data.get(input_name) or "").strip()
        if secret and not incoming:
            return str(stored or "")
        return incoming

    def _test_feed_connection(feed: Feed, field_values: Dict[str, str]) -> tuple[bool, str]:
        source_type = (feed.source_type or "").strip().lower()
        timeout_s = 10
        if source_type == "mwdb":
            from ..services.mwdb import test_mwdb_connection
            data = test_mwdb_connection(
                base_url=field_values.get("base_url", ""),
                auth_key=field_values.get("api_key", ""),
                timeout_s=timeout_s,
            )
            return True, f"MWDB connection OK. Organizations visible: {len(data.get('organizations', []))}."
        if source_type == "abusech":
            api_key = field_values.get("api_key", "")
            if not api_key:
                return False, "abuse.ch API key is required for connection test."
            with build_feed_session(source="abusech") as session:
                resp = session.post(
                    cfg.THREATFOX_API_URL,
                    headers={"Auth-Key": api_key, "User-Agent": "ioc-threat-platform/1.0"},
                    json={"query": "get_iocs", "days": 1},
                    timeout=timeout_s,
                )
                resp.raise_for_status()
            data = resp.json() if resp.content else {}
            status = str(data.get("query_status") or "ok")
            if status.lower() not in {"ok", "no_result"}:
                return False, f"abuse.ch test failed (query_status={status})."
            return True, f"abuse.ch connection OK (query_status={status})."
        if source_type == "misp":
            base_url = field_values.get("base_url", "").rstrip("/")
            api_key = field_values.get("api_key", "")
            if not base_url or not api_key:
                return False, "MISP URL and API key are required."
            with build_feed_session(source="misp") as session:
                resp = session.get(
                    f"{base_url}/users/view/me",
                    headers={"Authorization": api_key, "Accept": "application/json"},
                    timeout=timeout_s,
                    verify=cfg.MISP_VERIFY_SSL,
                )
                resp.raise_for_status()
            return True, "MISP connection OK."
        if source_type == "malwarebazaar":
            api_key = (cfg.ABUSECH_AUTH_KEY or "").strip()
            if not api_key:
                return False, "ABUSECH_AUTH_KEY is required for MalwareBazaar connection test."
            with build_feed_session(source="malwarebazaar") as session:
                resp = session.post(
                    cfg.MALWAREBAZAAR_API_URL,
                    headers={"Auth-Key": api_key, "User-Agent": "ioc-threat-platform/1.0"},
                    data={"query": "get_taginfo", "tag": "exe", "limit": "1"},
                    timeout=timeout_s,
                )
                resp.raise_for_status()
            data = resp.json() if resp.content else {}
            status = str(data.get("query_status") or "ok")
            if status.lower() not in {"ok", "no_result"}:
                return False, f"MalwareBazaar test failed (query_status={status})."
            return True, f"MalwareBazaar connection OK (query_status={status})."
        if source_type == "crowdsec":
            api_key = field_values.get("api_key", "")
            if not api_key:
                return False, "CrowdSec API key is required."
            list_ids = [x.strip() for x in (cfg.CROWDSEC_LISTS or "").split(",") if x.strip()]
            if not list_ids:
                return False, "Set CROWDSEC_LISTS to test CrowdSec connectivity."
            with build_feed_session(source="crowdsec") as session:
                resp = session.get(
                    f"https://api.crowdsec.net/v2/blocklists/{list_ids[0]}",
                    headers={"X-Api-Key": api_key},
                    timeout=timeout_s,
                )
                resp.raise_for_status()
            return True, "CrowdSec connection OK."
        return False, f"No connection test handler for source_type={source_type}."

    # ------------------------------------------------------------------ proxy test

    def _run_proxy_test() -> List[Dict[str, Any]]:
        targets = [
            {"key": "mwdb", "name": "MWDB", "url": "https://mwdb.cert.pl"},
            {"key": "abusech", "name": "abuse.ch", "url": "https://abuse.ch"},
            {"key": "certpl", "name": "CERT.PL", "url": "https://cert.pl"},
        ]
        out: List[Dict[str, Any]] = []
        for target in targets:
            t0 = time.time()
            row: Dict[str, Any] = {
                "target": target["name"],
                "url": target["url"],
                "status": "ERROR",
                "http": None,
                "latency_ms": None,
                "title": "",
                "notes": "",
                "error": "",
            }
            try:
                with build_feed_session(source="admin_proxy_test") as session:
                    resp = session.get(target["url"], timeout=(5, 10))
                row["http"] = int(resp.status_code)
                row["latency_ms"] = int((time.time() - t0) * 1000)
                content_type = str(resp.headers.get("Content-Type") or "")
                title = _extract_title_from_html(resp.text or "")
                row["title"] = title
                title_ok = _proxy_test_expected_match(target["key"], title)
                status_code_ok = int(resp.status_code) < 400
                content_type_ok = bool(content_type.strip())
                if status_code_ok and title_ok and content_type_ok:
                    row["status"] = "OK"
                elif status_code_ok:
                    row["status"] = "WARNING"
                else:
                    row["status"] = "ERROR"
                notes = []
                if not content_type_ok:
                    notes.append("missing Content-Type")
                if not title_ok:
                    notes.append("title mismatch")
                row["notes"] = ", ".join(notes) if notes else "ok"
            except Exception as exc:
                row["latency_ms"] = int((time.time() - t0) * 1000)
                row["status"] = "ERROR"
                row["error"] = redact_proxy_credentials(str(exc))
                row["notes"] = "request failed"
            out.append(row)
        return out

    # ------------------------------------------------------------------ namespace

    from types import SimpleNamespace

    return SimpleNamespace(
        source_templates=_source_templates,
        read_feed_enabled=_read_feed_enabled,
        ensure_default_feeds=_ensure_default_feeds,
        read_feed_config_state=_read_feed_config_state,
        is_valid_http_url=_is_valid_http_url,
        validate_feed_form=_validate_feed_form,
        fetch_mwdb_orgs=_fetch_mwdb_orgs,
        get_feed_field_value=_get_feed_field_value,
        test_feed_connection=_test_feed_connection,
        field_input_name=_field_input_name,
        feed_value_key=_feed_value_key,
        feed_secret_key=_feed_secret_key,
        run_proxy_test=_run_proxy_test,
        proxy_test_expected_match=_proxy_test_expected_match,
    )
