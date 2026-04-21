from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy.orm import Session

from ..config import Config
from ..db import SessionLocal
from ..settings_store import parse_bool_setting, runtime_override_or_env
from ..services.abusech import (
    _feed_secret_key,
    _feed_value_key,
    _validate_abusech_config,
    fetch_feodotracker_ips,
    fetch_hunting_fplist,
    fetch_threatfox_iocs,
    fetch_urlhaus_urls,
    fetch_yaraify_lookup_hashes,
    fetch_yaraify_tasks,
)
from ..services.common import _circuit_breaker, _dep_status, standardized_update_result
from ..services.crowdsec import _fetch_list
from ..services.malwarebazaar import _parse_dt as parse_malwarebazaar_dt, _parse_tag_list as parse_malwarebazaar_tags, fetch_malwarebazaar_by_tags
from ..services.misp import (
    TYPE_MAPPING,
    compute_confidence,
    extract_tlp_from_tags,
    tlp_exceeds_max,
    _fetch_misp_attributes,
    _normalize_value,
)
from ..services.mwdb import (
    _object_matches_group,
    _parse_org_list,
    _parse_tag_list as parse_mwdb_tags,
    fetch_mwdb_by_tags,
)
from ..runtime_env import push_runtime_env_overrides
from .contracts import FeedAdapter
from .pipeline import mark_feed_error, persist_batches
from .registry import AdapterRegistry
from .types import AdapterCapabilities, CanonicalIOC, FetchBatch

logger = logging.getLogger(__name__)


class BaseFeedAdapter:
    source_type: str
    capabilities: AdapterCapabilities

    def __init__(self, *, cfg: Config | None = None, db_factory: Callable[[], Session] = SessionLocal) -> None:
        self.cfg = cfg or Config()
        self._db_factory = db_factory

    def fetch_batches(self) -> list[FetchBatch]:
        raise NotImplementedError

    def execute(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        db = self._db_factory()
        try:
            batches = self.fetch_batches()
            results = persist_batches(db, batches, now=now)
            db.commit()
            return self._format_success(results)
        except Exception as exc:
            db.rollback()
            self._mark_failure(db, now=now, error=str(exc))
            db.commit()
            raise
        finally:
            db.close()

    def _format_success(self, results: dict[str, dict[str, Any]]) -> dict[str, Any]:
        fetched = sum(int(item.get("fetched", 0) or 0) for item in results.values())
        deactivated = sum(int(item.get("deactivated", 0) or 0) for item in results.values())
        errors = sum(int(item.get("errors", 0) or 0) for item in results.values())
        return standardized_update_result(
            fetched=fetched,
            deactivated=deactivated,
            errors=errors,
            details={"batches": results},
        )

    def _mark_failure(self, db: Session, *, now: datetime, error: str) -> None:
        mark_feed_error(db, source=self.source_type, source_id=None, now=now, error=error)


class CrowdSecFeedAdapter(BaseFeedAdapter):
    source_type = "crowdsec"
    capabilities = AdapterCapabilities(requires_authentication=True, supported_ioc_types=("ip",), supports_component_batches=True)

    def fetch_batches(self) -> list[FetchBatch]:
        if not self.cfg.CROWDSEC_API_KEY:
            raise RuntimeError("CROWDSEC_API_KEY not set")
        list_ids = [value.strip() for value in (self.cfg.CROWDSEC_LISTS or "").split(",") if value.strip()]
        batches: list[FetchBatch] = []
        for list_id in list_ids:
            values = _fetch_list(
                self.cfg.CROWDSEC_API_KEY,
                list_id,
                timeout_s=self.cfg.FEED_HTTP_TIMEOUT_S,
                retry_attempts=self.cfg.FEED_RETRY_ATTEMPTS,
                retry_base_delay_s=self.cfg.FEED_RETRY_BASE_DELAY_S,
            )
            items = tuple(
                CanonicalIOC(
                    value=value,
                    ioc_type="ip",
                    source_ref=list_id,
                    first_seen=None,
                    last_seen=None,
                    confidence=75,
                    tlp="AMBER",
                    metadata={"raw": value, "list_id": list_id},
                )
                for value in sorted(set(values))
            )
            batches.append(
                FetchBatch(
                    source="crowdsec",
                    items=items,
                    deactivation_scope=list_id,
                    feed_stats_source_id=list_id,
                    metadata={"list_id": list_id},
                    include_related_sources=False,
                )
            )
        return batches

    def _format_success(self, results: dict[str, dict[str, Any]]) -> dict[str, Any]:
        return standardized_update_result(
            fetched=sum(int(item.get("fetched", 0) or 0) for item in results.values()),
            deactivated=sum(int(item.get("deactivated", 0) or 0) for item in results.values()),
            errors=sum(int(item.get("errors", 0) or 0) for item in results.values()),
            details={"lists": results},
        )


class MispFeedAdapter(BaseFeedAdapter):
    source_type = "misp"
    capabilities = AdapterCapabilities(
        requires_authentication=True,
        supports_time_filtering=True,
        supported_ioc_types=("ip", "domain", "url", "hash", "email"),
    )

    def fetch_batches(self) -> list[FetchBatch]:
        if not self.cfg.MISP_URL or not self.cfg.MISP_API_KEY:
            _dep_status.update("misp", "down", error="not_configured", duration_ms=0)
            raise RuntimeError("not_configured")
        if _circuit_breaker.is_open("misp"):
            raise RuntimeError("circuit_open")
        attrs = _fetch_misp_attributes(self.cfg)
        max_tlp = (self.cfg.MISP_MAX_TLP or "AMBER").upper()
        grouped: dict[str, list[CanonicalIOC]] = {}
        tlp_skipped = 0
        for attr in attrs:
            attr_type = attr.get("type")
            mapped = TYPE_MAPPING.get(attr_type)
            if not mapped:
                continue
            value_norm, meta_extra = _normalize_value(attr_type, attr.get("value") or "")
            if not value_norm:
                continue
            event = attr.get("Event") or {}
            event_id = str(attr.get("event_id") or event.get("id") or "").strip()
            if not event_id:
                continue
            attr_tags = [tag.get("name") for tag in (attr.get("Tag") or []) if isinstance(tag, dict) and tag.get("name")]
            event_tags = [tag.get("name") for tag in (event.get("Tag") or []) if isinstance(tag, dict) and tag.get("name")] if isinstance(event, dict) else []
            tlp = extract_tlp_from_tags(attr_tags, event_tags)
            if tlp_exceeds_max(tlp, max_tlp):
                tlp_skipped += 1
                continue
            distribution = int(event.get("distribution") if isinstance(event, dict) and event.get("distribution") is not None else 3)
            tags = tuple({tag for tag in (attr_tags or []) + (event_tags or []) if tag})
            grouped.setdefault(event_id, []).append(
                CanonicalIOC(
                    value=value_norm,
                    ioc_type=mapped,
                    source_ref=event_id,
                    first_seen=None,
                    last_seen=None,
                    confidence=compute_confidence(distribution, list(tags)),
                    tlp=tlp,
                    tags=tags,
                    metadata={
                        "attribute_id": attr.get("id"),
                        "event_id": event_id,
                        "type": attr_type,
                        "category": attr.get("category"),
                        "comment": attr.get("comment"),
                        "timestamp": attr.get("timestamp"),
                        "distribution": distribution,
                        **meta_extra,
                    },
                )
            )
        batches = [
            FetchBatch(
                source="misp",
                items=tuple(items),
                deactivation_scope=event_id,
                feed_stats_source_id=None,
                metadata={"days": self.cfg.MISP_DAYS, "tlp_skipped": tlp_skipped},
            )
            for event_id, items in grouped.items()
        ]
        if not batches:
            batches = [FetchBatch(source="misp", items=tuple(), metadata={"days": self.cfg.MISP_DAYS, "tlp_skipped": tlp_skipped}, include_related_sources=False)]
        return batches

    def execute(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        if not self.cfg.MISP_URL or not self.cfg.MISP_API_KEY:
            db = self._db_factory()
            try:
                mark_feed_error(db, source="misp", source_id=None, now=now, error="not_configured")
                db.commit()
            finally:
                db.close()
            out = standardized_update_result(fetched=0, deactivated=0, errors=0, details={"skipped": 1, "reason": "not_configured"})
            out["skipped"] = 1
            out["reason"] = "not_configured"
            return out
        if _circuit_breaker.is_open("misp"):
            out = standardized_update_result(fetched=0, deactivated=0, errors=0, details={"skipped": 1, "reason": "circuit_open"})
            out["skipped"] = 1
            return out
        try:
            result = super().execute()
            _circuit_breaker.record_success("misp")
            _dep_status.update("misp", "ok")
            return result
        except Exception as exc:
            _circuit_breaker.record_failure(
                "misp",
                fail_threshold=max(1, int(self.cfg.MISP_CIRCUIT_FAIL_THRESHOLD)),
                cooldown_s=max(1, int(self.cfg.MISP_CIRCUIT_COOLDOWN_S)),
            )
            _dep_status.update("misp", "down", error=str(exc))
            raise


class MalwareBazaarFeedAdapter(BaseFeedAdapter):
    source_type = "malwarebazaar"
    capabilities = AdapterCapabilities(requires_authentication=True, supports_time_filtering=True, supports_tags=True, supported_ioc_types=("hash",))

    def fetch_batches(self) -> list[FetchBatch]:
        tags = parse_malwarebazaar_tags(self.cfg.MALWAREBAZAAR_TAGS)
        if not tags:
            return [FetchBatch(source="malwarebazaar", items=tuple(), metadata={"reason": "no_tags"}, include_related_sources=True)]
        since = parse_malwarebazaar_dt(self.cfg.MALWAREBAZAAR_SINCE_DATE) if self.cfg.MALWAREBAZAAR_SINCE_DATE else None
        rows = fetch_malwarebazaar_by_tags(
            base_url=self.cfg.MALWAREBAZAAR_API_URL,
            auth_key=self.cfg.ABUSECH_AUTH_KEY,
            tags=tags,
            since=since,
            until=None,
            limit=max(1, int(self.cfg.MALWAREBAZAAR_LIMIT)),
            timeout_s=max(1, int(self.cfg.FEED_HTTP_TIMEOUT_S)),
            retry_attempts=max(1, int(self.cfg.FEED_RETRY_ATTEMPTS)),
            retry_base_delay_s=max(0.1, float(self.cfg.FEED_RETRY_BASE_DELAY_S)),
        )
        items = tuple(
            CanonicalIOC(
                value=str(row.get("ioc_value") or ""),
                ioc_type=str(row.get("ioc_type") or "hash"),
                source_ref=str(row.get("source_ref") or row.get("ioc_value") or ""),
                first_seen=row.get("first_seen"),
                last_seen=row.get("last_seen"),
                confidence=int(row.get("confidence") or 60),
                tlp=str(row.get("tlp") or "GREEN"),
                tags=tuple(str(tag) for tag in (row.get("tags") or [])),
                metadata=dict(row.get("metadata") or {}),
            )
            for row in rows
        )
        return [FetchBatch(source="malwarebazaar", items=items, metadata={"tags": tags})]


class MwdbFeedAdapter(BaseFeedAdapter):
    source_type = "mwdb"
    capabilities = AdapterCapabilities(
        requires_authentication=True,
        supports_time_filtering=True,
        supports_tags=True,
        supports_custom_filter=True,
        supported_ioc_types=("hash", "ip", "domain", "url", "object_id"),
    )

    def execute(self) -> dict[str, Any]:
        if _circuit_breaker.is_open("mwdb"):
            return standardized_update_result(fetched=0, deactivated=0, errors=0, details={"skipped": 1, "reason": "circuit_open"})
        try:
            result = super().execute()
            _circuit_breaker.record_success("mwdb")
            _dep_status.update("mwdb", "ok")
            return result
        except Exception as exc:
            _circuit_breaker.record_failure(
                "mwdb",
                fail_threshold=max(1, int(self.cfg.MWDB_CIRCUIT_FAIL_THRESHOLD)),
                cooldown_s=max(1, int(self.cfg.MWDB_CIRCUIT_COOLDOWN_S)),
            )
            _dep_status.update("mwdb", "down", error=str(exc))
            raise

    def fetch_batches(self) -> list[FetchBatch]:
        now = datetime.now(timezone.utc)
        tags = parse_mwdb_tags(self.cfg.MWDB_TAGS)
        mode = "tags" if tags else "recent"
        since = None if self.cfg.MWDB_NO_TIME_LIMIT else (now - timedelta(days=max(1, int(self.cfg.MWDB_DAYS or 0)))) if int(self.cfg.MWDB_DAYS or 0) > 0 else None
        organizations = _parse_org_list(self.cfg.MWDB_ORGANIZATIONS)
        my_group = (self.cfg.MWDB_MY_GROUP or "").strip() or None
        telemetry: dict[str, Any] = {}
        rows = fetch_mwdb_by_tags(
            base_url=self.cfg.MWDB_URL,
            auth_key=self.cfg.MWDB_AUTH_KEY,
            tags=tags,
            custom_filter=self.cfg.MWDB_CUSTOM_FILTER,
            default_query=self.cfg.MWDB_DEFAULT_QUERY,
            mode=mode,
            since=since,
            until=None,
            organizations=organizations,
            my_group=my_group,
            limit=max(1, int(self.cfg.MWDB_LIMIT)),
            timeout_s=max(1, int(self.cfg.FEED_HTTP_TIMEOUT_S)),
            retry_attempts=max(1, int(self.cfg.FEED_RETRY_ATTEMPTS)),
            retry_base_delay_s=max(0.1, float(self.cfg.FEED_RETRY_BASE_DELAY_S)),
            telemetry=telemetry,
        )
        items = []
        for row in rows:
            metadata = dict(row.get("metadata") or {})
            metadata["my_group_match"] = _object_matches_group(metadata, my_group or "")
            items.append(
                CanonicalIOC(
                    value=str(row.get("ioc_value") or ""),
                    ioc_type=str(row.get("ioc_type") or ""),
                    source_ref=str(row.get("source_ref") or row.get("ioc_value") or ""),
                    first_seen=row.get("first_seen"),
                    last_seen=row.get("last_seen"),
                    confidence=int(row.get("confidence") or 60),
                    tlp=str(row.get("tlp") or "GREEN"),
                    tags=tuple(str(tag) for tag in (row.get("tags") or [])),
                    metadata=metadata,
                )
            )
        return [
            FetchBatch(
                source="mwdb",
                items=tuple(items),
                metadata={
                    "tags": tags,
                    "organizations": organizations,
                    "days": None if self.cfg.MWDB_NO_TIME_LIMIT else int(self.cfg.MWDB_DAYS or 0),
                    "mode": mode,
                    **telemetry,
                },
            )
        ]


class AbuseChFeedAdapter(BaseFeedAdapter):
    source_type = "abusech"
    capabilities = AdapterCapabilities(
        requires_authentication=True,
        supports_component_batches=True,
        supports_time_filtering=True,
        supported_ioc_types=("ip", "url", "hash", "domain", "object_id"),
    )

    def _load_runtime_config(self, db: Session) -> Config:
        override_pairs = {
            "ABUSECH_AUTH_KEY": ("abusech", "api_key", True),
            "YARAIFY_AUTH_KEY": ("abusech", "yaraify_auth_key", True),
            "YARAIFY_IDENTIFIER": ("abusech", "yaraify_identifier", False),
            "YARAIFY_LOOKUP_HASHES": ("abusech", "yaraify_lookup_hashes", False),
            "HUNTING_AUTH_KEY": ("abusech", "hunting_auth_key", True),
            "HUNTING_FPLIST_FORMAT": ("abusech", "hunting_fplist_format", False),
        }
        values = self.cfg.as_dict()
        for attr, (source_id, key, secret) in override_pairs.items():
            values[attr] = runtime_override_or_env(
                db,
                setting_key=_feed_secret_key(source_id, key) if secret else _feed_value_key(source_id, key),
                env_value=str(values.get(attr) or ""),
                secret=secret,
                cfg=self.cfg,
            )
        for attr, key in {
            "THREATFOX_ENABLED": "threatfox_enabled",
            "URLHAUS_ENABLED": "urlhaus_enabled",
            "FEODOTRACKER_ENABLED": "feodotracker_enabled",
            "YARAIFY_ENABLED": "yaraify_enabled",
            "HUNTING_FPLIST_ENABLED": "hunting_fplist_enabled",
        }.items():
            values[attr] = parse_bool_setting(
                runtime_override_or_env(
                    db,
                    setting_key=_feed_value_key("abusech", key),
                    env_value="1" if bool(values.get(attr)) else "0",
                    secret=False,
                    cfg=self.cfg,
                )
            )
        env_values = {key: None if value is None else str(value) for key, value in values.items()}
        with push_runtime_env_overrides(env_values):
            return Config()

    def fetch_batches(self) -> list[FetchBatch]:
        db = self._db_factory()
        try:
            runtime_cfg = self._load_runtime_config(db)
        finally:
            db.close()
        _validate_abusech_config(runtime_cfg)
        retry_attempts = max(1, int(runtime_cfg.ABUSECH_RETRY_ATTEMPTS))
        retry_base_delay_s = max(0.1, float(runtime_cfg.ABUSECH_RETRY_BASE_DELAY_S))
        timeout_s = max(1, int(runtime_cfg.ABUSECH_TIMEOUT_S))
        auth_key = runtime_cfg.ABUSECH_AUTH_KEY
        batches: list[FetchBatch] = []

        def _ioc_batch(source: str, rows: list[dict[str, Any]]) -> None:
            items = tuple(
                CanonicalIOC(
                    value=str(row.get("ioc_value") or ""),
                    ioc_type=str(row.get("ioc_type") or ""),
                    source_ref=str(row.get("source_ref") or row.get("ioc_value") or ""),
                    first_seen=row.get("first_seen"),
                    last_seen=row.get("last_seen"),
                    confidence=int(row.get("confidence") or 60),
                    tlp=str(row.get("tlp") or "GREEN"),
                    tags=tuple(str(tag) for tag in (row.get("tags") or [])),
                    metadata=dict(row.get("metadata") or {}),
                )
                for row in rows
            )
            batches.append(FetchBatch(source=source, items=items, metadata={"fetched": len(items)}))

        if runtime_cfg.THREATFOX_ENABLED:
            _ioc_batch(
                "threatfox",
                list(
                    fetch_threatfox_iocs(
                        api_url=runtime_cfg.THREATFOX_API_URL,
                        auth_key=runtime_cfg.THREATFOX_AUTH_KEY or auth_key,
                        days=max(1, int(runtime_cfg.THREATFOX_DAYS)),
                        limit=max(1, int(runtime_cfg.THREATFOX_LIMIT)),
                        timeout_s=timeout_s,
                        retry_attempts=retry_attempts,
                        retry_base_delay_s=retry_base_delay_s,
                    )
                ),
            )
        if runtime_cfg.URLHAUS_ENABLED:
            _ioc_batch(
                "urlhaus",
                list(
                    fetch_urlhaus_urls(
                        url=runtime_cfg.URLHAUS_FEED_URL,
                        limit=max(1, int(runtime_cfg.URLHAUS_LIMIT)),
                        timeout_s=timeout_s,
                        retry_attempts=retry_attempts,
                        retry_base_delay_s=retry_base_delay_s,
                    )
                ),
            )
        if runtime_cfg.FEODOTRACKER_ENABLED:
            _ioc_batch(
                "feodotracker",
                list(
                    fetch_feodotracker_ips(
                        url=runtime_cfg.FEODOTRACKER_FEED_URL,
                        limit=max(1, int(runtime_cfg.FEODOTRACKER_LIMIT)),
                        timeout_s=timeout_s,
                        retry_attempts=retry_attempts,
                        retry_base_delay_s=retry_base_delay_s,
                    )
                ),
            )
        if runtime_cfg.YARAIFY_ENABLED:
            yaraify_key = runtime_cfg.YARAIFY_AUTH_KEY or auth_key
            identifier = (runtime_cfg.YARAIFY_IDENTIFIER or "").strip()
            if identifier:
                rows = list(
                    fetch_yaraify_tasks(
                        api_url=runtime_cfg.YARAIFY_API_URL,
                        auth_key=yaraify_key,
                        identifier=identifier,
                        task_status=runtime_cfg.YARAIFY_TASK_STATUS,
                        limit=max(1, int(runtime_cfg.YARAIFY_LIMIT)),
                        timeout_s=timeout_s,
                        retry_attempts=retry_attempts,
                        retry_base_delay_s=retry_base_delay_s,
                    )
                )
            else:
                rows = list(
                    fetch_yaraify_lookup_hashes(
                        api_url=runtime_cfg.YARAIFY_API_URL,
                        auth_key=yaraify_key,
                        search_terms=[item.strip() for item in (runtime_cfg.YARAIFY_LOOKUP_HASHES or "").split(",") if item.strip()],
                        limit=max(1, int(runtime_cfg.YARAIFY_LIMIT)),
                        timeout_s=timeout_s,
                        retry_attempts=retry_attempts,
                        retry_base_delay_s=retry_base_delay_s,
                    )
                )
            _ioc_batch("yaraify", rows)
        if runtime_cfg.HUNTING_FPLIST_ENABLED:
            _ioc_batch(
                "abusech_hunting_fplist",
                list(
                    fetch_hunting_fplist(
                        api_url=runtime_cfg.HUNTING_API_URL,
                        auth_key=runtime_cfg.HUNTING_AUTH_KEY or auth_key,
                        response_format=runtime_cfg.HUNTING_FPLIST_FORMAT,
                        limit=max(1, int(runtime_cfg.HUNTING_FPLIST_LIMIT)),
                        timeout_s=timeout_s,
                        retry_attempts=retry_attempts,
                        retry_base_delay_s=retry_base_delay_s,
                    )
                ),
            )
        return batches

    def _format_success(self, results: dict[str, dict[str, Any]]) -> dict[str, Any]:
        out = standardized_update_result(
            fetched=sum(int(item.get("fetched", 0) or 0) for item in results.values()),
            deactivated=sum(int(item.get("deactivated", 0) or 0) for item in results.values()),
            errors=sum(int(item.get("errors", 0) or 0) for item in results.values()),
            details={"sources": results},
        )
        out.update(results)
        return out


def build_feed_registry(cfg: Config | None = None) -> AdapterRegistry[FeedAdapter]:
    registry: AdapterRegistry[FeedAdapter] = AdapterRegistry()
    registry.register("crowdsec", CrowdSecFeedAdapter(cfg=cfg))
    registry.register("misp", MispFeedAdapter(cfg=cfg))
    registry.register("malwarebazaar", MalwareBazaarFeedAdapter(cfg=cfg))
    registry.register("mwdb", MwdbFeedAdapter(cfg=cfg))
    registry.register("abusech", AbuseChFeedAdapter(cfg=cfg))
    return registry
