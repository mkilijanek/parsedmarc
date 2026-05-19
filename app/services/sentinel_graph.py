from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, cast
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .common import build_feed_session


def _runtime_post(url: str, **kwargs: Any):
    with build_feed_session(source="sentinel_graph") as session:
        return session.post(url, **kwargs)


requests = SimpleNamespace(post=_runtime_post)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _thumbprint_to_x5t(thumbprint: str) -> str:
    raw = (thumbprint or "").strip().replace(":", "").lower()
    if not raw:
        return ""
    try:
        return _b64url(bytes.fromhex(raw))
    except Exception:
        return ""


def build_graph_indicator(row: Any, *, expiration_days: int = 30) -> Dict[str, Any]:
    value = str(getattr(row, "value", "") or "").strip()
    ioc_type = str(getattr(row, "type", "") or "").strip().lower()
    source = str(getattr(row, "source", "") or "").strip()
    confidence = int(getattr(row, "confidence", 50) or 50)
    tlp = str(getattr(row, "tlp", "GREEN") or "GREEN").upper()

    expires = datetime.now(timezone.utc) + timedelta(days=max(1, expiration_days))
    base: Dict[str, Any] = {
        "action": "alert",
        "description": f"IOC exported from ioc-service (source={source})",
        "confidence": max(0, min(100, confidence)),
        "tlpLevel": tlp.lower(),
        "targetProduct": "Azure Sentinel",
        "expirationDateTime": expires.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    if ioc_type == "ip":
        base["networkIPv4"] = value
    elif ioc_type == "domain":
        base["domainName"] = value
    elif ioc_type == "url":
        base["url"] = value
    elif ioc_type == "hash":
        hash_len = len(value)
        hash_type = "unknown"
        if hash_len == 32:
            hash_type = "md5"
        elif hash_len == 40:
            hash_type = "sha1"
        elif hash_len == 64:
            hash_type = "sha256"
        base["fileHashType"] = hash_type
        base["fileHashValue"] = value
    else:
        # Graph TI needs typed indicator fields. Unknown IOC types are skipped by caller.
        return {}
    return base


def graph_access_token(
    *,
    tenant_id: str,
    client_id: str,
    scope: str,
    auth_mode: str,
    client_secret: str,
    cert_private_key_pem: str,
    cert_thumbprint: str,
    timeout_s: int = 20,
) -> str:
    tenant = (tenant_id or "").strip()
    cid = (client_id or "").strip()
    if not tenant or not cid:
        raise RuntimeError("Azure tenant_id/client_id are required")
    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    payload: Dict[str, str] = {
        "client_id": cid,
        "grant_type": "client_credentials",
        "scope": (scope or "https://graph.microsoft.com/.default").strip(),
    }

    mode = (auth_mode or "client_secret").strip().lower()
    if mode == "certificate":
        pem = (cert_private_key_pem or "").strip()
        if not pem:
            raise RuntimeError("certificate mode requires private key PEM")
        key = cast(rsa.RSAPrivateKey, load_pem_private_key(pem.encode("utf-8"), password=None))
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        x5t = _thumbprint_to_x5t(cert_thumbprint)
        if x5t:
            header["x5t"] = x5t
        claims = {
            "aud": token_url,
            "iss": cid,
            "sub": cid,
            "jti": uuid.uuid4().hex,
            "nbf": now - 60,
            "exp": now + 600,
        }
        signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))}.{_b64url(json.dumps(claims, separators=(',', ':')).encode('utf-8'))}".encode("utf-8")
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        assertion = f"{signing_input.decode('utf-8')}.{_b64url(sig)}"
        payload["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        payload["client_assertion"] = assertion
    else:
        secret = (client_secret or "").strip()
        if not secret:
            raise RuntimeError("client_secret mode requires client secret")
        payload["client_secret"] = secret

    resp = requests.post(token_url, data=payload, timeout=max(1, timeout_s))  # nosec B113 — timeout is present
    resp.raise_for_status()
    data = resp.json() if resp.content else {}
    token = str(data.get("access_token") or "")
    if not token:
        raise RuntimeError("Graph token response missing access_token")
    return token


def push_indicators_to_graph(
    *,
    indicators: Iterable[Any],
    tenant_id: str,
    client_id: str,
    scope: str = "https://graph.microsoft.com/.default",
    auth_mode: str = "client_secret",
    client_secret: str = "",
    cert_private_key_pem: str = "",
    cert_thumbprint: str = "",
    endpoint_url: str = "https://graph.microsoft.com/beta/security/tiIndicators/submitTiIndicators",
    chunk_size: int = 100,
    timeout_s: int = 30,
) -> Dict[str, Any]:
    token = graph_access_token(
        tenant_id=tenant_id,
        client_id=client_id,
        scope=scope,
        auth_mode=auth_mode,
        client_secret=client_secret,
        cert_private_key_pem=cert_private_key_pem,
        cert_thumbprint=cert_thumbprint,
        timeout_s=timeout_s,
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    mapped: List[Dict[str, Any]] = []
    skipped = 0
    for row in indicators:
        obj = build_graph_indicator(row)
        if not obj:
            skipped += 1
            continue
        mapped.append(obj)

    sent = 0
    failed = 0
    chunks = 0
    errors: List[str] = []
    step = max(1, int(chunk_size or 100))
    for i in range(0, len(mapped), step):
        batch = mapped[i : i + step]
        chunks += 1
        try:
            resp = requests.post(endpoint_url, headers=headers, json={"value": batch}, timeout=max(1, timeout_s))  # nosec B113 — timeout is present
            resp.raise_for_status()
            sent += len(batch)
        except Exception as exc:
            failed += len(batch)
            errors.append(str(exc))

    return {
        "fetched": len(mapped),
        "deactivated": 0,
        "errors": failed,
        "details": {
            "sent": sent,
            "failed": failed,
            "skipped": skipped,
            "chunks": chunks,
            "endpoint_hash": hashlib.sha256(endpoint_url.encode("utf-8")).hexdigest()[:12],
            "errors": errors[:20],
        },
    }
