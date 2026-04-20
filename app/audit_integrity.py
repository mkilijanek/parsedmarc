from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value or "")


def audit_payload(
    *,
    action: str,
    entity_type: str | None,
    entity_id: int | None,
    user_id: str | None,
    ip_address: str | None,
    metadata: dict | None,
    created_at: Any,
    previous_hash: str | None,
) -> str:
    """Build the canonical representation signed into the audit hash chain."""
    payload = {
        "action": action,
        "entity_type": entity_type or "",
        "entity_id": entity_id,
        "user_id": user_id or "",
        "ip_address": str(ip_address or ""),
        "metadata": metadata or {},
        "created_at": _timestamp(created_at),
        "previous_hash": previous_hash or "",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def audit_log_hash(secret_key: str, payload: str) -> str:
    return hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def signed_audit_hash(
    *,
    secret_key: str,
    action: str,
    entity_type: str | None,
    entity_id: int | None,
    user_id: str | None,
    ip_address: str | None,
    metadata: dict | None,
    created_at: Any,
    previous_hash: str | None,
) -> str:
    return audit_log_hash(
        secret_key,
        audit_payload(
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            user_id=user_id,
            ip_address=ip_address,
            metadata=metadata,
            created_at=created_at,
            previous_hash=previous_hash,
        ),
    )


def verify_audit_chain(audit_rows: list[Any], *, secret_key: str) -> dict[str, Any]:
    """Verify signed audit rows while allowing unsigned legacy rows before rollout."""
    previous_hash = ""
    verified_count = 0
    legacy_count = 0
    signed_started = False
    failures: list[dict[str, Any]] = []

    for row in audit_rows:
        row_hash = str(getattr(row, "log_hash", "") or "")
        row_previous_hash = str(getattr(row, "previous_hash", "") or "")

        if not row_hash:
            legacy_count += 1
            if signed_started:
                failures.append({"id": getattr(row, "id", None), "reason": "unsigned_row_after_signed_chain_started"})
            continue

        signed_started = True
        if row_previous_hash != previous_hash:
            failures.append({"id": getattr(row, "id", None), "reason": "previous_hash_mismatch"})

        expected_hash = signed_audit_hash(
            secret_key=secret_key,
            action=str(getattr(row, "action", "") or ""),
            entity_type=getattr(row, "entity_type", None),
            entity_id=getattr(row, "entity_id", None),
            user_id=getattr(row, "user_id", None),
            ip_address=getattr(row, "ip_address", None),
            metadata=getattr(row, "metadata_", None) or {},
            created_at=getattr(row, "created_at", None),
            previous_hash=row_previous_hash,
        )
        if not hmac.compare_digest(row_hash, expected_hash):
            failures.append({"id": getattr(row, "id", None), "reason": "log_hash_mismatch"})

        previous_hash = row_hash
        verified_count += 1

    return {
        "valid": not failures,
        "verified_count": verified_count,
        "legacy_count": legacy_count,
        "failure_count": len(failures),
        "failures": failures,
        "last_hash": previous_hash,
    }
