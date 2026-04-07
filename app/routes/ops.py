from __future__ import annotations

import logging
from typing import Any, Dict

from .ops_admin import register_ops_admin_routes
from .ops_api import register_ops_api_routes


def register_ops_routes(
    app,
    *,
    limiter,
    cfg,
    logger: logging.Logger,
    scheduler_state: Dict[str, Any],
    deps: Dict[str, Any],
) -> None:
    register_ops_admin_routes(
        app,
        limiter=limiter,
        cfg=cfg,
        logger=logger,
        deps=deps,
    )
    register_ops_api_routes(
        app,
        limiter=limiter,
        logger=logger,
        scheduler_state=scheduler_state,
        deps=deps,
    )
