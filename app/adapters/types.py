from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AdapterCapabilities:
    supports_time_filtering: bool = False
    supports_tags: bool = False
    supports_custom_filter: bool = False
    supports_component_batches: bool = False
    requires_authentication: bool = False
    supported_ioc_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class CanonicalIOC:
    value: str
    ioc_type: str
    source_ref: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: int = 60
    tlp: str = "GREEN"
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_mapping(self) -> dict[str, Any]:
        return {
            "ioc_value": self.value,
            "ioc_type": self.ioc_type,
            "source_ref": self.source_ref,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": self.confidence,
            "tlp": self.tlp,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class FetchBatch:
    source: str
    items: tuple[CanonicalIOC, ...]
    deactivation_scope: str | None = None
    feed_stats_source_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    include_related_sources: bool = True

