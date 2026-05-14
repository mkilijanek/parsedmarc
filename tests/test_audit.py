from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


class TestAuditIntegrityEdgeCases:

    def test_verify_audit_chain_empty_list(self):
        from app.audit_integrity import verify_audit_chain
        # Empty list should be valid (no records to violate)
        result = verify_audit_chain([], secret_key="test-secret-key-32-chars-minimum!")
        assert result["valid"] is True

    def test_signed_audit_hash_deterministic(self):
        from app.audit_integrity import signed_audit_hash
        h1 = signed_audit_hash(
            secret_key="key",
            action="test",
            entity_type="indicator",
            entity_id=1,
            user_id="user",
            ip_address="127.0.0.1",
            metadata={},
            created_at=datetime(2024, 1, 1, 0, 0, 0),
            previous_hash="",
        )
        h2 = signed_audit_hash(
            secret_key="key",
            action="test",
            entity_type="indicator",
            entity_id=1,
            user_id="user",
            ip_address="127.0.0.1",
            metadata={},
            created_at=datetime(2024, 1, 1, 0, 0, 0),
            previous_hash="",
        )
        assert h1 == h2

    def test_signed_audit_hash_changes_with_different_inputs(self):
        from app.audit_integrity import signed_audit_hash
        h1 = signed_audit_hash(
            secret_key="key", action="create", entity_type="x", entity_id=1,
            user_id="u", ip_address="1.2.3.4", metadata={},
            created_at=datetime(2024, 1, 1), previous_hash=""
        )
        h2 = signed_audit_hash(
            secret_key="key", action="delete", entity_type="x", entity_id=1,
            user_id="u", ip_address="1.2.3.4", metadata={},
            created_at=datetime(2024, 1, 1), previous_hash=""
        )
        assert h1 != h2
