from __future__ import annotations

import logging
import json
import sys
from typing import Any, Dict

class JsonFormatter(logging.Formatter):
    """Strict JSON log formatter."""
    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k in {"args","msg","levelname","levelno","pathname","filename","module","exc_info","exc_text","stack_info","lineno","funcName","created","msecs","relativeCreated","thread","threadName","processName","process","name"}:
                continue
            if k.startswith("_"):
                continue
            base[k] = v
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(base, ensure_ascii=True, default=str)

def setup_logging(level: str = "INFO") -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(lvl)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(lvl)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]

    # Reduce noisy libs
    for noisy in ("urllib3", "requests", "pymisp"):
        logging.getLogger(noisy).setLevel(max(lvl, logging.WARNING))
