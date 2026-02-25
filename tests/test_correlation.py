from __future__ import annotations

from datetime import datetime, timezone

from app.models import Indicator
from app.services.correlation import query_correlations


def test_query_correlations_groups_across_sources(test_db):
    now = datetime.now(timezone.utc)
    test_db.add_all([
        Indicator(
            value="shared.example.org",
            type="domain",
            source="threatfox",
            source_id="1",
            confidence=70,
            tlp="GREEN",
            is_active=True,
            tags=["malware"],
            metadata_={"threatfox": {"enrichment": {"domain_root": "example.org"}}},
            first_seen=now,
            last_seen=now,
        ),
        Indicator(
            value="shared.example.org",
            type="domain",
            source="mwdb",
            source_id="2",
            confidence=80,
            tlp="GREEN",
            is_active=True,
            tags=["apt"],
            metadata_={"mwdb": {"enrichment": {"domain_root": "example.org"}}},
            first_seen=now,
            last_seen=now,
        ),
    ])
    test_db.commit()

    groups = query_correlations(test_db, min_sources=2, limit=100, ioc_type="domain")
    assert len(groups) == 1
    g = groups[0]
    assert g["value"] == "shared.example.org"
    assert g["type"] == "domain"
    assert g["source_count"] == 2
    assert "malware" in g["tags"]
    assert "apt" in g["tags"]
    assert g["enrichment"]["domain_root"] == "example.org"
