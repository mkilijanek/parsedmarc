from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict

class JsonLikeFormatter(logging.Formatter):
    """Structured-ish logging without requiring extra deps.

    Uses `extra={...}` and prints a single line key=value pairs.
    """
    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "level": record.levelname,
            "name": record.name,
            "msg": record.getMessage(),
        }
        # Include common context keys if present
        for k, v in record.__dict__.items():
            if k in {"args","msg","levelname","levelno","pathname","filename","module","exc_info","exc_text","stack_info","lineno","funcName","created","msecs","relativeCreated","thread","threadName","processName","process","name"}:
                continue
            if k.startswith("_"):
                continue
            # Keep it reasonably small
            base[k] = v
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)

        # Render as key=value pairs (safe for syslog/grep)
        parts = []
        for k in sorted(base.keys()):
            v = base[k]
            s = str(v)
            # quote if contains spaces
            if any(c.isspace() for c in s) or "=" in s:
                s = s.replace('"', '\"')
                s = f'"{s}"'
            parts.append(f"{k}={s}")
        return " ".join(parts)

def setup_logging(level: str = "INFO") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(lvl)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(lvl)
    handler.setFormatter(JsonLikeFormatter())
    root.handlers = [handler]

    # Reduce noisy libs
    for noisy in ("urllib3", "requests", "pymisp"):
        logging.getLogger(noisy).setLevel(max(lvl, logging.WARNING))
