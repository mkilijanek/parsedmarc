from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session

from ..cache import get_redis
from ..metrics import (
    quality_dedup_merged_total,
    quality_dropped_invalid_total,
    quality_normalized_total,
)
from ..models import FeedStats, Indicator
from ..services.common import standardized_update_result
from ..services.quality import canonicalize_row, dedup_rows
from .types import CanonicalIOC, FetchBatch

logger = logging.getLogger(__name__)


def db_retry(operation, *, attempts: int = 3, base_delay_s: float = 0.2):
    last_exc: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            return operation()
        except (OperationalError, DBAPIError) as exc:
            last_exc = exc
            if attempt >= attempts:
                raise
            time.sleep(base_delay_s * attempt)
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("db_retry exhausted without executing operation")


def _prepare_items(source: str, items: tuple[CanonicalIOC, ...]) -> list[CanonicalIOC]:
    canonical_rows: list[dict[str, Any]] = []
    for item in items:
        normalized, reason = canonicalize_row(item.as_mapping(), source=source)
        if normalized is None:
            quality_dropped_invalid_total.labels(source=source, reason=(reason or "invalid")).inc()
            continue
        canonical_rows.append(normalized)
    deduped_rows, merged = dedup_rows(canonical_rows)
    quality_normalized_total.labels(source=source).inc(len(deduped_rows))
    if merged:
        quality_dedup_merged_total.labels(source=source).inc(merged)
    prepared: list[CanonicalIOC] = []
    for row in deduped_rows:
        prepared.append(
            CanonicalIOC(
                value=str(row.get("ioc_value") or "").strip(),
                ioc_type=str(row.get("ioc_type") or "").strip(),
                source_ref=str(row.get("source_ref") or row.get("ioc_value") or "").strip(),
                first_seen=row.get("first_seen"),
                last_seen=row.get("last_seen"),
                confidence=int(row.get("confidence") or 60),
                tlp=str(row.get("tlp") or "GREEN"),
                tags=tuple(str(tag) for tag in (row.get("tags") or [])),
                metadata=dict(row.get("metadata") or {}),
            )
        )
    return prepared


def invalidate_feed_caches() -> None:
    try:
        redis_client = get_redis()
        for pattern in ("health*", "indicators_html*", "export*", "correlations*"):
            cursor = 0
            while True:
                cursor, keys = redis_client.scan(cursor=cursor, match=pattern, count=100)
                if keys:
                    redis_client.delete(*keys)
                if cursor == 0:
                    break
    except Exception:
        logger.warning("feed_cache_invalidation_failed", exc_info=True)


def _persist_batch(db: Session, batch: FetchBatch, *, now: datetime) -> dict[str, Any]:
    items = _prepare_items(batch.source, batch.items)
    incoming_values = {item.value for item in items if item.value}
    incoming_types = {item.ioc_type for item in items if item.ioc_type}

    if batch.deactivation_scope is None:
        deactivate_stmt = (
            update(Indicator)
            .where(Indicator.source == batch.source, Indicator.is_active == True)  # noqa: E712
            .values(is_active=False, last_seen=now)
            .execution_options(synchronize_session=False)
        )
        if incoming_values:
            deactivate_stmt = (
                update(Indicator)
                .where(
                    Indicator.source == batch.source,
                    Indicator.is_active == True,  # noqa: E712
                    ~Indicator.value.in_(list(incoming_values)),
                )
                .values(is_active=False, last_seen=now)
                .execution_options(synchronize_session=False)
            )
    else:
        deactivate_stmt = (
            update(Indicator)
            .where(
                Indicator.source == batch.source,
                Indicator.source_id == batch.deactivation_scope,
                Indicator.is_active == True,  # noqa: E712
            )
            .values(is_active=False, last_seen=now)
            .execution_options(synchronize_session=False)
        )
        if incoming_values:
            deactivate_stmt = (
                update(Indicator)
                .where(
                    Indicator.source == batch.source,
                    Indicator.source_id == batch.deactivation_scope,
                    Indicator.is_active == True,  # noqa: E712
                    ~Indicator.value.in_(list(incoming_values)),
                )
                .values(is_active=False, last_seen=now)
                .execution_options(synchronize_session=False)
            )
    db.execute(deactivate_stmt)

    related_sources_map: dict[tuple[str, str], set[str]] = {}
    if batch.include_related_sources and incoming_values and incoming_types:
        related_rows = (
            db.query(Indicator.value, Indicator.type, Indicator.source)
            .filter(Indicator.value.in_(list(incoming_values)))
            .filter(Indicator.type.in_(list(incoming_types)))
            .all()
        )
        for value, ioc_type, rel_source in related_rows:
            related_sources_map.setdefault((str(value), str(ioc_type)), set()).add(str(rel_source))

    for item in items:
        metadata_obj = dict(item.metadata)
        if batch.include_related_sources:
            related_sources = set(related_sources_map.get((item.value, item.ioc_type), set()))
            related_sources.add(batch.source)
            metadata_obj["related_sources"] = sorted(related_sources)
        db.execute(
            pg_insert(Indicator.__table__).values(
                value=item.value,
                type=item.ioc_type,
                source=batch.source,
                source_id=item.source_ref,
                first_seen=item.first_seen or now,
                last_seen=item.last_seen or now,
                confidence=item.confidence,
                tlp=item.tlp,
                is_active=True,
                metadata={batch.source: metadata_obj},
                tags=list(item.tags),
            ).on_conflict_do_update(
                index_elements=["value", "source", "source_id"],
                set_={
                    "last_seen": item.last_seen or now,
                    "is_active": True,
                    "confidence": item.confidence,
                    "tlp": item.tlp,
                    "metadata": {batch.source: metadata_obj},
                    "tags": list(item.tags),
                },
            )
        )

    feed_metadata = {"fetched": len(items), **dict(batch.metadata)}
    db.execute(
        pg_insert(FeedStats.__table__).values(
            source=batch.source,
            source_id=batch.feed_stats_source_id,
            last_update=now,
            last_fetch_status="success",
            last_fetch_error=None,
            metadata=feed_metadata,
        ).on_conflict_do_update(
            index_elements=["source", "source_id"],
            set_={
                "last_update": now,
                "last_fetch_status": "success",
                "last_fetch_error": None,
                "metadata": feed_metadata,
            },
        )
    )
    return standardized_update_result(
        fetched=len(items),
        deactivated=0,
        errors=0,
        details={"source": batch.source},
    )


def persist_batches(db: Session, batches: list[FetchBatch], *, now: datetime | None = None) -> dict[str, dict[str, Any]]:
    current_now = now or datetime.now(timezone.utc)
    results: dict[str, dict[str, Any]] = {}
    for batch in batches:
        results_key = batch.feed_stats_source_id or batch.source
        results[results_key] = db_retry(lambda batch=batch: _persist_batch(db, batch, now=current_now))
    invalidate_feed_caches()
    return results


def mark_feed_error(db: Session, *, source: str, source_id: str | None, now: datetime, error: str, metadata: dict[str, Any] | None = None) -> None:
    db.execute(
        pg_insert(FeedStats.__table__).values(
            source=source,
            source_id=source_id,
            last_update=now,
            last_fetch_status="error",
            last_fetch_error=error[:2000],
            metadata=metadata or {},
        ).on_conflict_do_update(
            index_elements=["source", "source_id"],
            set_={
                "last_update": now,
                "last_fetch_status": "error",
                "last_fetch_error": error[:2000],
                "metadata": metadata or {},
            },
        )
    )
