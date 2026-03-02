from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _domain_root(domain: str) -> str:
    parts = [p for p in (domain or "").strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    # Pragmatic approximation; avoids external PSL dependency.
    return ".".join(parts[-2:])


def enrich_metadata(*, value: str, ioc_type: str, metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
    md = dict(metadata or {})
    enrichment: Dict[str, Any] = dict(md.get("enrichment") or {})
    t = (ioc_type or "").strip().lower()
    v = (value or "").strip()

    if t == "url":
        p = urlparse(v)
        host = (p.hostname or "").lower()
        enrichment["url_host"] = host
        enrichment["url_scheme"] = p.scheme.lower() if p.scheme else ""
        if host:
            try:
                ip = ipaddress.ip_address(host)
                enrichment["url_host_type"] = "ip"
                enrichment["url_host_is_private"] = bool(ip.is_private)
            except Exception:
                enrichment["url_host_type"] = "domain"
                enrichment["url_host_root"] = _domain_root(host)

    if t == "ip":
        try:
            ip = ipaddress.ip_address(v)
            enrichment["ip_version"] = ip.version
            enrichment["ip_is_private"] = bool(ip.is_private)
            enrichment["ip_is_global"] = bool(ip.is_global)
            enrichment["ip_is_multicast"] = bool(ip.is_multicast)
        except ValueError:
            logger.debug("enrichment_ip_parse_failed", extra={"value": v})

    if t == "domain":
        dv = v.lower().strip(".")
        enrichment["domain_root"] = _domain_root(dv)
        enrichment["domain_label_count"] = len([p for p in dv.split(".") if p])

    if t == "hash":
        n = len(v)
        hash_type = {
            32: "md5",
            40: "sha1",
            64: "sha256",
            96: "sha3_384",
            128: "sha512",
        }.get(n, "unknown")
        enrichment["hash_len"] = n
        enrichment["hash_type"] = hash_type

    md["enrichment"] = enrichment
    return md
