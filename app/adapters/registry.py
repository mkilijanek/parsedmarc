from __future__ import annotations

from typing import Dict, Generic, Iterable, TypeVar


T = TypeVar("T")


class _Registry(Generic[T]):
    def __init__(self) -> None:
        self._factories: Dict[str, T] = {}

    def register(self, key: str, factory: T) -> None:
        self._factories[str(key)] = factory

    def get(self, key: str) -> T:
        try:
            return self._factories[str(key)]
        except KeyError as exc:
            raise KeyError(f"Unknown registry key: {key}") from exc

    def keys(self) -> Iterable[str]:
        return self._factories.keys()


class AdapterRegistry(_Registry[T]):
    pass


class ExportAdapterRegistry(_Registry[T]):
    pass
