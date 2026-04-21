from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .types import AdapterCapabilities, FetchBatch


@runtime_checkable
class FeedAdapter(Protocol):
    source_type: str
    capabilities: AdapterCapabilities

    def fetch_batches(self) -> list[FetchBatch]:
        ...

    def execute(self) -> dict[str, Any]:
        ...


@runtime_checkable
class ExportAdapter(Protocol):
    export_type: str

    def execute(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        ...
