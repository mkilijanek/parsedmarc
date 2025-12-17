from __future__ import annotations

import os
import re
from flask import request, abort

_MAX_QUERY_LEN = 500

def validate_search_query(query: str) -> bool:
    if query is None:
        return True
    if len(query) > _MAX_QUERY_LEN:
        return False
    # Defense-in-depth: even though we compile to SQLAlchemy safely, reject common SQLi payload markers
    dangerous = ["--", ";", "/*", "*/", "DROP", "DELETE", "INSERT", "UPDATE", "ALTER"]
    up = query.upper()
    return not any(d in up for d in dangerous)

def enforce_allowed_hosts() -> None:
    allowed = os.getenv("ALLOWED_HOSTS", "*").strip()
    if allowed == "*" or not allowed:
        return
    allowed_set = {h.strip().lower() for h in allowed.split(",") if h.strip()}
    host = (request.host.split(":")[0] if request.host else "").lower()
    if host and host not in allowed_set:
        abort(400, description="Invalid Host header")
