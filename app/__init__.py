from __future__ import annotations

from typing import Any


def create_app(*args: Any, **kwargs: Any):
    # Lazy import keeps package import side-effect free (important for Alembic/env tooling).
    from .main import create_app as _create_app

    return _create_app(*args, **kwargs)


__all__ = ["create_app"]
