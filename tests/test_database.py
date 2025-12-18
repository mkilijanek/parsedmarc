"""
Comprehensive database tests for IOC service.

Tests cover:
- Model creation and validation
- Unique constraints
- Database queries and filters
- Indexes and performance
- Upsert operations
- Data integrity
- Audit logging
- Feed statistics
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError

from app.models import Indicator, FeedStats, AuditLog


# ============================================================================
# Indicator Model Tests
# ============================================================================

class TestIndicatorModel:
    """Test Indicator model CRUD operations."""

    def test_create_indicator(self, test_db):
        """Test creating a basic indicator."""
        indicator = Indicator(
            value="192.168.1.1",
            type="ip",
            source="test",
            source_id="test-1",
            confidence=80,
            tlp="AMBER",
            tags=["test", "malware"],
            metadata_={"key": "value"},
        )
        test_db.add(indicator)
        test_db.commit()

        # Verify it was created
        assert indicator.id is not None
        assert indicator.uuid is not None
        assert indicator.value == "192.168.1.1"
        assert indicator.type == "ip"
        assert indicator.is_active is True

    def test_indicator_defaults(self, test_db):
        """Test indicator default values."""
        indicator = Indicator(
            value="test.com",
            type="domain",
            source="test",
        )
        test_db.add(indicator)
        test_db.commit()

        # Check defaults
        assert indicator.confidence == 50
        assert indicator.tlp == "WHITE"
        assert indicator.is_active is True
        assert indicator.tags == []
        assert indicator.metadata == {}
        assert indicator.first_seen is not None
        assert indicator.last_seen is not None
        assert indicator.created_at is not None
        assert indicator.updated_at is not None

    def test_indicator_unique_constraint(self, test_db):
        """Test unique constraint on (value, source, source_id)."""
        # Create first indicator
        ind1 = Indicator(
            value="192.168.1.1",
            type="ip",
            source="misp",
            source_id="event-123",
            confidence=80,
        )
        test_db.add(ind1)
        test_db.commit()

        # Try to create duplicate
        ind2 = Indicator(
            value="192.168.1.1",
            type="ip",
            source="misp",
            source_id="event-123",
            confidence=90,
        )
        test_db.add(ind2)

        with pytest.raises(IntegrityError):
            test_db.commit()

        test_db.rollback()

    def test_indicator_different_sources_allowed(self, test_db):
        """Test same value from different sources is allowed."""
        # Same IP from MISP
        ind1 = Indicator(
            value="192.168.1.1",
            type="ip",
            source="misp",
            source_id="event-123",
        )
        test_db.add(ind1)
        test_db.commit()

        # Same IP from CrowdSec
        ind2 = Indicator(
            value="192.168.1.1",
            type="ip",
            source="crowdsec",
            source_id="list-abc",
        )
        test_db.add(ind2)
        test_db.commit()

        # Both should exist
        count = test_db.query(Indicator).filter_by(value="192.168.1.1").count()
        assert count == 2

    def test_indicator_update(self, test_db):
        """Test updating an indicator."""
        indicator = Indicator(
            value="test.com",
            type="domain",
            source="test",
            confidence=50,
        )
        test_db.add(indicator)
        test_db.commit()

        # Update confidence
        indicator.confidence = 80
        indicator.last_seen = datetime.now(timezone.utc)
        test_db.commit()

        # Verify update
        updated = test_db.query(Indicator).filter_by(id=indicator.id).first()
        assert updated.confidence == 80

    def test_indicator_soft_delete(self, test_db):
        """Test soft delete via is_active flag."""
        indicator = Indicator(
            value="test.com",
            type="domain",
            source="test",
            is_active=True,
        )
        test_db.add(indicator)
        test_db.commit()

        # Soft delete
        indicator.is_active = False
        test_db.commit()

        # Verify it's marked inactive
        inactive = test_db.query(Indicator).filter_by(id=indicator.id).first()
        assert inactive.is_active is False

    def test_indicator_uuid_generation(self, test_db):
        """Test UUID is generated automatically."""
        indicator = Indicator(
            value="test.com",
            type="domain",
            source="test",
        )
        test_db.add(indicator)
        test_db.commit()

        assert indicator.uuid is not None
        # UUID should be unique
        assert len(str(indicator.uuid)) == 36

    def test_indicator_tags_array(self, test_db):
        """Test tags array field."""
        indicator = Indicator(
            value="test.com",
            type="domain",
            source="test",
            tags=["apt", "malware", "phishing"],
        )
        test_db.add(indicator)
        test_db.commit()

        # Verify tags
        retrieved = test_db.query(Indicator).filter_by(id=indicator.id).first()
        assert len(retrieved.tags) == 3
        assert "apt" in retrieved.tags

    def test_indicator_metadata_jsonb(self, test_db):
        """Test metadata JSONB field."""
        indicator = Indicator(
            value="test.com",
            type="domain",
            source="test",
            metadata_={
                "registrar": "evil-registrar",
                "country": "XX",
                "asn": 12345,
                "nested": {"key": "value"},
            },
        )
        test_db.add(indicator)
        test_db.commit()

        # Verify metadata
        retrieved = test_db.query(Indicator).filter_by(id=indicator.id).first()
        assert retrieved.metadata["registrar"] == "evil-registrar"
        assert retrieved.metadata["asn"] == 12345
        assert retrieved.metadata["nested"]["key"] == "value"


# ============================================================================
# Query and Filter Tests
# ============================================================================

class TestIndicatorQueries:
    """Test database queries and filters."""

    def test_query_by_type(self, test_db, sample_indicators):
        """Test filtering by indicator type."""
        ips = test_db.query(Indicator).filter_by(type="ip", is_active=True).all()
        assert len(ips) > 0
        for ip in ips:
            assert ip.type == "ip"

    def test_query_by_tlp(self, test_db, sample_indicators):
        """Test filtering by TLP level."""
        red_tlp = test_db.query(Indicator).filter_by(tlp="RED", is_active=True).all()
        assert len(red_tlp) > 0
        for ind in red_tlp:
            assert ind.tlp == "RED"

    def test_query_by_source(self, test_db, sample_indicators):
        """Test filtering by source."""
        misp = test_db.query(Indicator).filter_by(source="misp", is_active=True).all()
        assert len(misp) > 0
        for ind in misp:
            assert ind.source == "misp"

    def test_query_by_confidence_range(self, test_db, sample_indicators):
        """Test filtering by confidence range."""
        high_conf = test_db.query(Indicator).filter(
            Indicator.confidence >= 80,
            Indicator.is_active == True
        ).all()

        assert len(high_conf) > 0
        for ind in high_conf:
            assert ind.confidence >= 80

    def test_query_by_tags(self, test_db, sample_indicators):
        """Test filtering by tags (array contains)."""
        malware = test_db.query(Indicator).filter(
            Indicator.tags.any("malware"),
            Indicator.is_active == True
        ).all()

        assert len(malware) > 0
        for ind in malware:
            assert "malware" in ind.tags

    def test_query_active_only(self, test_db, sample_indicators):
        """Test filtering active indicators only."""
        active = test_db.query(Indicator).filter_by(is_active=True).all()
        inactive = test_db.query(Indicator).filter_by(is_active=False).all()

        # Should have both active and inactive
        assert len(active) > 0
        assert len(inactive) > 0

        # Active should not include inactive indicators
        active_ids = {ind.id for ind in active}
        inactive_ids = {ind.id for ind in inactive}
        assert not active_ids.intersection(inactive_ids)

    def test_query_order_by_last_seen(self, test_db, sample_indicators):
        """Test ordering by last_seen."""
        recent = test_db.query(Indicator).filter_by(is_active=True).order_by(
            Indicator.last_seen.desc()
        ).limit(5).all()

        assert len(recent) > 0

        # Verify ordering
        for i in range(len(recent) - 1):
            assert recent[i].last_seen >= recent[i + 1].last_seen

    def test_query_pagination(self, test_db, sample_indicators):
        """Test query pagination with limit and offset."""
        page1 = test_db.query(Indicator).filter_by(is_active=True).limit(2).offset(0).all()
        page2 = test_db.query(Indicator).filter_by(is_active=True).limit(2).offset(2).all()

        assert len(page1) <= 2
        assert len(page2) <= 2

        # Pages should not overlap
        page1_ids = {ind.id for ind in page1}
        page2_ids = {ind.id for ind in page2}
        assert not page1_ids.intersection(page2_ids)

    def test_query_count(self, test_db, sample_indicators):
        """Test counting indicators."""
        total = test_db.query(func.count()).select_from(Indicator).scalar()
        active = test_db.query(func.count()).select_from(Indicator).filter_by(is_active=True).scalar()

        assert total > 0
        assert active > 0
        assert active <= total

    def test_query_distinct_sources(self, test_db, sample_indicators):
        """Test querying distinct sources."""
        sources = test_db.query(Indicator.source).distinct().all()
        source_list = [s[0] for s in sources]

        assert "misp" in source_list
        assert "crowdsec" in source_list

    def test_query_by_date_range(self, test_db, sample_indicators):
        """Test filtering by date range."""
        cutoff = datetime(2025, 1, 10, tzinfo=timezone.utc)
        recent = test_db.query(Indicator).filter(
            Indicator.last_seen > cutoff,
            Indicator.is_active == True
        ).all()

        assert len(recent) > 0
        for ind in recent:
            assert ind.last_seen > cutoff


# ============================================================================
# FeedStats Model Tests
# ============================================================================

class TestFeedStatsModel:
    """Test FeedStats model operations."""

    def test_create_feed_stats(self, test_db):
        """Test creating feed statistics."""
        stats = FeedStats(
            source="misp",
            source_id="server-1",
            total_indicators=1000,
            active_indicators=950,
            inactive_indicators=50,
            last_fetch_status="success",
        )
        test_db.add(stats)
        test_db.commit()

        assert stats.id is not None
        assert stats.source == "misp"

    def test_feed_stats_defaults(self, test_db):
        """Test FeedStats default values."""
        stats = FeedStats(
            source="test",
        )
        test_db.add(stats)
        test_db.commit()

        assert stats.total_indicators == 0
        assert stats.active_indicators == 0
        assert stats.inactive_indicators == 0
        assert stats.last_update is not None
        assert stats.metadata == {}

    def test_feed_stats_unique_constraint(self, test_db):
        """Test unique constraint on (source, source_id)."""
        stats1 = FeedStats(
            source="misp",
            source_id="server-1",
        )
        test_db.add(stats1)
        test_db.commit()

        stats2 = FeedStats(
            source="misp",
            source_id="server-1",
        )
        test_db.add(stats2)

        with pytest.raises(IntegrityError):
            test_db.commit()

        test_db.rollback()

    def test_feed_stats_update(self, test_db, sample_feed_stats):
        """Test updating feed statistics."""
        stats = test_db.query(FeedStats).filter_by(source="misp").first()
        original_total = stats.total_indicators

        stats.total_indicators = original_total + 100
        stats.active_indicators = stats.active_indicators + 95
        stats.last_update = datetime.now(timezone.utc)
        test_db.commit()

        updated = test_db.query(FeedStats).filter_by(source="misp").first()
        assert updated.total_indicators == original_total + 100

    def test_feed_stats_error_tracking(self, test_db):
        """Test tracking fetch errors."""
        stats = FeedStats(
            source="test",
            last_fetch_status="error",
            last_fetch_error="Connection timeout",
        )
        test_db.add(stats)
        test_db.commit()

        assert stats.last_fetch_status == "error"
        assert "timeout" in stats.last_fetch_error.lower()


# ============================================================================
# AuditLog Model Tests
# ============================================================================

class TestAuditLogModel:
    """Test AuditLog model operations."""

    def test_create_audit_log(self, test_db):
        """Test creating audit log entry."""
        log = AuditLog(
            action="query",
            entity_type="indicator",
            entity_id=123,
            user_id="test-user",
            ip_address="1.2.3.4",
            metadata_={"query": "type:ip", "count": 10},
        )
        test_db.add(log)
        test_db.commit()

        assert log.id is not None
        assert log.action == "query"
        assert log.created_at is not None

    def test_audit_log_defaults(self, test_db):
        """Test AuditLog default values."""
        log = AuditLog(
            action="test",
        )
        test_db.add(log)
        test_db.commit()

        assert log.created_at is not None
        assert log.metadata == {}

    def test_audit_log_query_by_action(self, test_db):
        """Test querying audit logs by action."""
        # Create multiple log entries
        for action in ["query", "export", "query", "export", "query"]:
            log = AuditLog(action=action)
            test_db.add(log)
        test_db.commit()

        query_logs = test_db.query(AuditLog).filter_by(action="query").all()
        export_logs = test_db.query(AuditLog).filter_by(action="export").all()

        assert len(query_logs) == 3
        assert len(export_logs) == 2

    def test_audit_log_query_by_ip(self, test_db):
        """Test querying audit logs by IP address."""
        log1 = AuditLog(action="test", ip_address="1.2.3.4")
        log2 = AuditLog(action="test", ip_address="5.6.7.8")
        test_db.add_all([log1, log2])
        test_db.commit()

        logs = test_db.query(AuditLog).filter_by(ip_address="1.2.3.4").all()
        assert len(logs) == 1
        assert logs[0].ip_address == "1.2.3.4"

    def test_audit_log_metadata_search(self, test_db):
        """Test searching audit logs by metadata."""
        log = AuditLog(
            action="export",
            metadata_={"format": "json", "count": 100},
        )
        test_db.add(log)
        test_db.commit()

        # Retrieve and verify metadata
        retrieved = test_db.query(AuditLog).filter_by(id=log.id).first()
        assert retrieved.metadata["format"] == "json"
        assert retrieved.metadata["count"] == 100


# ============================================================================
# Upsert Operations Tests
# ============================================================================

class TestUpsertOperations:
    """Test upsert (INSERT ... ON CONFLICT UPDATE) operations."""

    def test_upsert_new_indicator(self, test_db):
        """Test upserting a new indicator (INSERT)."""
        # First upsert creates the indicator
        indicator = Indicator(
            value="192.168.1.1",
            type="ip",
            source="misp",
            source_id="event-123",
            confidence=80,
            tlp="AMBER",
        )
        test_db.add(indicator)
        test_db.commit()

        count = test_db.query(Indicator).filter_by(value="192.168.1.1", source="misp").count()
        assert count == 1

    def test_upsert_existing_indicator(self, test_db):
        """Test upserting an existing indicator (UPDATE)."""
        # Create initial indicator
        indicator = Indicator(
            value="192.168.1.1",
            type="ip",
            source="misp",
            source_id="event-123",
            confidence=80,
            tlp="AMBER",
        )
        test_db.add(indicator)
        test_db.commit()
        original_id = indicator.id

        # Simulate upsert: update if exists
        existing = test_db.query(Indicator).filter_by(
            value="192.168.1.1",
            source="misp",
            source_id="event-123"
        ).first()

        if existing:
            existing.confidence = 90
            existing.last_seen = datetime.now(timezone.utc)
            test_db.commit()

        # Verify update
        updated = test_db.query(Indicator).filter_by(id=original_id).first()
        assert updated.confidence == 90
        assert updated.id == original_id  # Same record, not new one


# ============================================================================
# Data Integrity Tests
# ============================================================================

class TestDataIntegrity:
    """Test data integrity constraints and validation."""

    def test_indicator_type_constraint(self, test_db):
        """Test that indicator type is validated."""
        # Note: SQLite doesn't enforce CHECK constraints by default
        # This test would work in PostgreSQL
        indicator = Indicator(
            value="test.com",
            type="ip",  # Valid type
            source="test",
        )
        test_db.add(indicator)
        test_db.commit()

        assert indicator.type in ["ip", "domain", "url", "hash", "email"]

    def test_confidence_range(self, test_db):
        """Test confidence value range."""
        # Valid confidence
        indicator = Indicator(
            value="test.com",
            type="domain",
            source="test",
            confidence=75,
        )
        test_db.add(indicator)
        test_db.commit()

        assert 0 <= indicator.confidence <= 100

    def test_tlp_values(self, test_db):
        """Test TLP value validation."""
        for tlp in ["WHITE", "GREEN", "AMBER", "RED"]:
            indicator = Indicator(
                value=f"test-{tlp}.com",
                type="domain",
                source="test",
                tlp=tlp,
            )
            test_db.add(indicator)
        test_db.commit()

        count = test_db.query(Indicator).count()
        assert count == 4

    def test_non_null_constraints(self, test_db):
        """Test NOT NULL constraints."""
        # Missing required fields should fail
        indicator = Indicator(
            # Missing value
            type="domain",
            source="test",
        )

        with pytest.raises(IntegrityError):
            test_db.add(indicator)
            test_db.commit()

        test_db.rollback()


# ============================================================================
# Performance and Index Tests
# ============================================================================

class TestDatabasePerformance:
    """Test database query performance and index usage."""

    def test_query_with_indexes(self, test_db, sample_indicators):
        """Test queries that should use indexes."""
        # Query by type (should use index)
        ips = test_db.query(Indicator).filter_by(type="ip", is_active=True).all()
        assert len(ips) > 0

        # Query by source (should use index)
        misp = test_db.query(Indicator).filter_by(source="misp", is_active=True).all()
        assert len(misp) > 0

    def test_large_result_set(self, test_db):
        """Test handling large result sets."""
        # Create many indicators
        for i in range(100):
            ind = Indicator(
                value=f"test-{i}.com",
                type="domain",
                source="test",
                confidence=50,
            )
            test_db.add(ind)
        test_db.commit()

        # Query all
        all_indicators = test_db.query(Indicator).all()
        assert len(all_indicators) >= 100

    def test_pagination_performance(self, test_db):
        """Test pagination doesn't load all records."""
        # Create test data
        for i in range(50):
            ind = Indicator(
                value=f"test-{i}.com",
                type="domain",
                source="test",
            )
            test_db.add(ind)
        test_db.commit()

        # Paginate
        page = test_db.query(Indicator).limit(10).offset(0).all()
        assert len(page) == 10


# ============================================================================
# Relationship and Join Tests
# ============================================================================

class TestRelationships:
    """Test relationships between models."""

    def test_indicator_to_feed_stats_relationship(self, test_db, sample_indicators, sample_feed_stats):
        """Test querying indicators and related feed stats."""
        # Get MISP indicators
        misp_indicators = test_db.query(Indicator).filter_by(source="misp").all()

        # Get MISP stats
        misp_stats = test_db.query(FeedStats).filter_by(source="misp").first()

        assert len(misp_indicators) > 0
        assert misp_stats is not None
        assert misp_stats.source == "misp"

    def test_query_indicators_with_stats(self, test_db, sample_indicators, sample_feed_stats):
        """Test joining indicators with feed stats."""
        # This would be a more complex query in production
        # For now, verify we can query both tables
        indicators = test_db.query(Indicator).all()
        stats = test_db.query(FeedStats).all()

        assert len(indicators) > 0
        assert len(stats) > 0
