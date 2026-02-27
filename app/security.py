from __future__ import annotations

import os
import re
from flask import request as flask_request, abort
from typing import Optional

_MAX_QUERY_LEN = 500


class _RequestAccessor:
    """Patch-friendly request accessor for tests."""

    __func__ = None

    @property
    def host(self):
        return flask_request.host

    @property
    def headers(self):
        return flask_request.headers

    @property
    def remote_addr(self):
        return flask_request.remote_addr


request = _RequestAccessor()

def validate_search_query(query: str) -> bool:
    if query is None:
        return True
    if len(query) > _MAX_QUERY_LEN:
        return False
    # Defense-in-depth: reject known SQL meta-markers while allowing quoted Kibana syntax.
    dangerous = ["--", ";", "/*", "*/", "XP_", "0X"]
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

def get_client_ip() -> Optional[str]:
    """
    Safely extract client IP address from request.

    SECURITY: X-Forwarded-For can be spoofed. Only trust it if you're behind
    a trusted proxy. Configure TRUSTED_PROXY_COUNT to indicate how many
    proxies to trust (counting from the right of X-Forwarded-For).

    Returns the most reliable IP address available.
    """
    trusted_proxy_count = int(os.getenv("TRUSTED_PROXY_COUNT", "0"))

    if trusted_proxy_count > 0 and "X-Forwarded-For" in request.headers:
        # X-Forwarded-For format: client, proxy1, proxy2, ...
        forwarded = request.headers.get("X-Forwarded-For", "")
        ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]

        if ips:
            # Take the IP that is trusted_proxy_count positions from the right
            # Example: if XFF = "client, proxy1, proxy2" and trusted=1, take proxy1 position
            # But we want the client, so we take from position: len(ips) - trusted_proxy_count - 1
            idx = len(ips) - trusted_proxy_count - 1
            if 0 <= idx < len(ips):
                return ips[idx]
            # If index out of range, fall back to first IP
            return ips[0]

    # Fallback to direct connection IP
    return request.remote_addr
