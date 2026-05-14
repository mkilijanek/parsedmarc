from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestEnrichmentEdgeCases:

    def test_enrich_metadata_empty(self):
        from app.services.enrichment import enrich_metadata
        result = enrich_metadata(value="1.2.3.4", ioc_type="ip", metadata={})
        assert isinstance(result, dict)

    def test_enrich_metadata_domain(self):
        from app.services.enrichment import enrich_metadata
        result = enrich_metadata(value="evil.com", ioc_type="domain", metadata={})
        assert isinstance(result, dict)

    def test_enrich_metadata_url(self):
        from app.services.enrichment import enrich_metadata
        result = enrich_metadata(value="http://evil.com/path", ioc_type="url", metadata={})
        assert isinstance(result, dict)

    def test_enrich_metadata_preserves_existing(self):
        from app.services.enrichment import enrich_metadata
        existing = {"key": "value"}
        result = enrich_metadata(value="1.2.3.4", ioc_type="ip", metadata=existing)
        assert "key" in result

    def test_enrich_metadata_none_metadata(self):
        from app.services.enrichment import enrich_metadata
        result = enrich_metadata(value="1.2.3.4", ioc_type="ip", metadata=None)
        assert isinstance(result, dict)
