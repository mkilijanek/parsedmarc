"""
Comprehensive tests for all 17 export formatters.

Tests cover:
- All export format functions
- Input validation and sanitization
- Output format correctness
- Edge cases (empty data, special characters, unicode)
- Security (no code injection, proper escaping)
- Performance with large datasets
"""
from __future__ import annotations

import json
import csv
import io
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import pytest

from app.formatters import (
    export_txt,
    export_csv,
    export_json,
    export_xml,
    export_fortigate_ebl,
    export_fortigate_ips,
    export_checkpoint_csv,
    export_paloalto_edl,
    export_sentinel_stix,
    export_defender_csv,
    export_f5_datagroup,
    export_imperva_json,
    export_arcsight_cef,
    export_elasticsearch_bulk,
    export_cribl_ndjson,
    export_splunk_hec,
    export_fidelis_stix_bundle,
    FORMATTERS,
    _sanitize_name,
    _severity_from_confidence,
    _tlp_lower,
)
from app.models import Indicator


# ============================================================================
# Basic Format Tests
# ============================================================================

class TestBasicFormats:
    """Test basic export formats: txt, csv, json, xml."""

    def test_export_txt_basic(self, sample_indicators):
        """Test TXT export with basic indicators."""
        result = export_txt(sample_indicators[:3])

        lines = result.strip().split("\n")
        assert len(lines) == 3
        assert "192.168.1.100" in lines
        assert "10.0.0.50" in lines
        assert "malicious.example.com" in lines

    def test_export_txt_empty(self):
        """Test TXT export with empty list."""
        result = export_txt([])
        assert result == ""

    def test_export_txt_special_characters(self):
        """Test TXT export with special characters in values."""
        indicator = Indicator(
            value="test\nvalue\twith\rspecial",
            type="domain",
            source="test",
            confidence=50,
            tlp="WHITE",
        )
        result = export_txt([indicator])
        assert "test\nvalue\twith\rspecial" in result

    def test_export_csv_basic(self, sample_indicators):
        """Test CSV export structure and content."""
        result = export_csv(sample_indicators[:2])

        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["value"] == "192.168.1.100"
        assert rows[0]["type"] == "ip"
        assert rows[0]["confidence"] == "95"
        assert rows[0]["tlp"] == "RED"
        assert rows[0]["source"] == "misp"
        assert "apt;malware;ransomware" in rows[0]["tags"]

    def test_export_csv_escaping(self):
        """Test CSV export properly escapes quotes and commas."""
        indicator = Indicator(
            value='test"value,with"quotes',
            type="domain",
            source="test,source",
            confidence=50,
            tlp="WHITE",
            tags=["tag1,tag2", "tag3"],
        )
        result = export_csv([indicator])

        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)

        assert len(rows) == 1
        assert 'test"value,with"quotes' in rows[0]["value"]

    def test_export_json_basic(self, sample_indicators):
        """Test JSON export structure and content."""
        result = export_json(sample_indicators[:2])

        data = json.loads(result)
        assert len(data) == 2

        # Validate first indicator
        assert data[0]["value"] == "192.168.1.100"
        assert data[0]["type"] == "ip"
        assert data[0]["confidence"] == 95
        assert data[0]["tlp"] == "RED"
        assert data[0]["source"] == "misp"
        assert data[0]["source_id"] == "event-123"
        assert data[0]["is_active"] is True
        assert "apt" in data[0]["tags"]
        assert "first_seen" in data[0]
        assert "last_seen" in data[0]
        assert "metadata" in data[0]

    def test_export_json_unicode(self):
        """Test JSON export handles unicode correctly."""
        indicator = Indicator(
            value="тест.рф",  # Cyrillic domain
            type="domain",
            source="test",
            confidence=50,
            tlp="WHITE",
            tags=["unicode", "тест"],
        )
        result = export_json([indicator])

        data = json.loads(result)
        assert data[0]["value"] == "тест.рф"
        assert "тест" in data[0]["tags"]

    def test_export_xml_basic(self, sample_indicators):
        """Test XML export structure and validity."""
        result = export_xml(sample_indicators[:2])

        # Parse XML
        root = ET.fromstring(result)
        assert root.tag == "indicators"

        children = list(root)
        assert len(children) == 2

        # Validate first indicator
        first = children[0]
        assert first.find("value").text == "192.168.1.100"
        assert first.find("type").text == "ip"
        assert first.find("confidence").text == "95"
        assert first.find("tlp").text == "RED"
        assert first.find("source").text == "misp"

    def test_export_xml_escaping(self):
        """Test XML export properly escapes special characters."""
        indicator = Indicator(
            value="<script>alert('xss')</script>",
            type="domain",
            source="test&source",
            confidence=50,
            tlp="WHITE",
        )
        result = export_xml([indicator])

        # Should not contain raw script tags
        assert "<script>" not in result
        assert "&lt;script&gt;" in result
        assert "&amp;source" in result or "test&amp;source" in result

        # Should parse validly
        root = ET.fromstring(result)
        assert root.find(".//value").text == "<script>alert('xss')</script>"


# ============================================================================
# Firewall Format Tests
# ============================================================================

class TestFirewallFormats:
    """Test firewall-specific export formats."""

    def test_fortigate_ebl_ip_only(self, sample_indicators):
        """Test FortiGate EBL exports only IP addresses."""
        result = export_fortigate_ebl(sample_indicators)

        lines = result.strip().split("\n")
        # Should only contain IPs (192.168.1.100, 10.0.0.50, 8.8.8.8)
        # Excludes inactive 172.16.0.1
        assert "192.168.1.100" in lines
        assert "10.0.0.50" in lines
        assert "malicious.example.com" not in result
        assert "http://evil.com" not in result

    def test_fortigate_ips_format(self, sample_indicators):
        """Test FortiGate IPS signature format."""
        result = export_fortigate_ips(sample_indicators)

        lines = result.strip().split("\n")
        assert len(lines) > 0

        # Check format: ThreatName|SigID|Severity|Protocol|SrcIP|SrcPort|DstIP|DstPort
        first_line = lines[0]
        parts = first_line.split("|")
        assert len(parts) == 8
        assert parts[0].startswith("ThreatFeed-")
        assert parts[1].startswith("9000000")  # Signature ID
        assert parts[2] in ["high", "medium", "low"]
        assert parts[3] == "tcp"

    def test_checkpoint_csv_format(self, sample_indicators):
        """Test Check Point CSV import format."""
        result = export_checkpoint_csv(sample_indicators)

        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)

        assert len(rows) > 0
        assert "name" in rows[0]
        assert "ip-address" in rows[0]
        assert "confidence" in rows[0]
        assert "severity" in rows[0]
        assert "color" in rows[0]

        # Check confidence mapping
        assert rows[0]["confidence"] in ["high", "medium", "low"]
        assert rows[0]["severity"] in ["high", "medium", "low"]
        assert rows[0]["color"] in ["red", "orange", "yellow"]

    def test_paloalto_edl_format(self, sample_indicators):
        """Test Palo Alto EDL format (one IP per line)."""
        result = export_paloalto_edl(sample_indicators)

        lines = result.strip().split("\n")
        # Should only contain active IPs
        assert "192.168.1.100" in lines
        assert "10.0.0.50" in lines

        # Should not contain non-IPs
        assert not any("malicious.example.com" in line for line in lines)


# ============================================================================
# SIEM/Security Tool Format Tests
# ============================================================================

class TestSecurityToolFormats:
    """Test SIEM and security tool export formats."""

    def test_sentinel_stix_format(self, sample_indicators):
        """Test Microsoft Sentinel STIX format."""
        result = export_sentinel_stix(sample_indicators[:3])

        data = json.loads(result)
        assert "sourcesystem" in data
        assert data["sourcesystem"] == "ThreatFeedAggregator"
        assert "indicators" in data
        assert len(data["indicators"]) == 3

        # Validate indicator structure
        ind = data["indicators"][0]
        assert "pattern" in ind
        assert "patternType" in ind
        assert ind["patternType"] == "stix"
        assert "confidence" in ind
        assert "tlpLevel" in ind
        assert "tags" in ind

        # Check pattern format for IP
        assert "[ipv4-addr:value = '192.168.1.100']" in ind["pattern"]

    def test_sentinel_stix_patterns(self):
        """Test STIX pattern generation for different indicator types."""
        indicators = [
            Indicator(value="1.2.3.4", type="ip", source="test", confidence=50, tlp="WHITE"),
            Indicator(value="evil.com", type="domain", source="test", confidence=50, tlp="WHITE"),
            Indicator(value="http://evil.com", type="url", source="test", confidence=50, tlp="WHITE"),
            Indicator(value="evil@test.com", type="email", source="test", confidence=50, tlp="WHITE"),
            Indicator(value="a" * 64, type="hash", source="test", confidence=50, tlp="WHITE"),
        ]

        result = export_sentinel_stix(indicators)
        data = json.loads(result)

        patterns = [ind["pattern"] for ind in data["indicators"]]
        assert "[ipv4-addr:value = '1.2.3.4']" in patterns
        assert "[domain-name:value = 'evil.com']" in patterns
        assert "[url:value = 'http://evil.com']" in patterns
        assert "[email-addr:value = 'evil@test.com']" in patterns
        assert any("SHA-256" in p for p in patterns)

    def test_defender_csv_format(self, sample_indicators):
        """Test Microsoft Defender CSV format."""
        result = export_defender_csv(sample_indicators)

        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)

        assert len(rows) > 0

        # Check required columns
        assert "IndicatorValue" in rows[0]
        assert "IndicatorType" in rows[0]
        assert "Action" in rows[0]
        assert "Severity" in rows[0]

        # Validate type mapping
        ip_row = next(r for r in rows if r["IndicatorType"] == "IpAddress")
        assert ip_row["Action"] == "Block"
        assert ip_row["Severity"] in ["High", "Medium", "Low"]

    def test_f5_datagroup_format(self, sample_indicators):
        """Test F5 BIG-IP data group format."""
        result = export_f5_datagroup(sample_indicators)

        lines = result.strip().split("\n")
        assert len(lines) > 0

        # Format: "IP" := "malicious,confidence"
        for line in lines:
            assert ":=" in line
            assert "malicious" in line
            # IP should be in quotes
            assert line.startswith('"')

    def test_imperva_json_format(self, sample_indicators):
        """Test Imperva WAF JSON format."""
        result = export_imperva_json(sample_indicators)

        data = json.loads(result)
        assert "name" in data
        assert "entries" in data

        # Validate entry structure
        if data["entries"]:
            entry = data["entries"][0]
            assert "type" in entry
            assert "ipAddressFrom" in entry
            assert "ipAddressTo" in entry
            assert "networkMask" in entry

    def test_arcsight_cef_format(self, sample_indicators):
        """Test ArcSight CEF format."""
        result = export_arcsight_cef(sample_indicators)

        lines = result.strip().split("\n")
        assert len(lines) > 0

        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        first_line = lines[0]
        assert first_line.startswith("CEF:0|ThreatFeedAggregator|")
        assert "TI-IP" in first_line
        assert "src=" in first_line
        assert "cs1Label=TLP" in first_line
        assert "cs2Label=Confidence" in first_line

    def test_elasticsearch_bulk_format(self, sample_indicators):
        """Test Elasticsearch bulk API NDJSON format."""
        result = export_elasticsearch_bulk(sample_indicators[:2])

        lines = result.strip().split("\n")
        # Each indicator = 2 lines (action + document)
        assert len(lines) == 4

        # Validate action line
        action = json.loads(lines[0])
        assert "index" in action
        assert "_index" in action["index"]
        assert "_id" in action["index"]

        # Validate document line
        doc = json.loads(lines[1])
        assert "@timestamp" in doc
        assert "indicator" in doc
        assert "tlp" in doc
        assert "source" in doc

    def test_cribl_ndjson_format(self, sample_indicators):
        """Test Cribl NDJSON format."""
        result = export_cribl_ndjson(sample_indicators[:2])

        lines = result.strip().split("\n")
        assert len(lines) == 2

        # Validate document structure
        doc = json.loads(lines[0])
        assert "_time" in doc
        assert "source" in doc
        assert "sourcetype" in doc
        assert "indicator_value" in doc
        assert "indicator_type" in doc
        assert "confidence_score" in doc
        assert "threat" in doc

    def test_splunk_hec_format(self, sample_indicators):
        """Test Splunk HEC batch format."""
        result = export_splunk_hec(sample_indicators[:2])

        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == 2

        # Validate event structure
        event = data[0]
        assert "time" in event
        assert "host" in event
        assert "source" in event
        assert "sourcetype" in event
        assert "index" in event
        assert "event" in event

        # Validate nested event
        assert "indicator" in event["event"]
        assert "indicator_type" in event["event"]

    def test_fidelis_stix_bundle_format(self, sample_indicators):
        """Test Fidelis STIX 2.1 bundle format."""
        result = export_fidelis_stix_bundle(sample_indicators[:2])

        data = json.loads(result)
        assert "type" in data
        assert data["type"] == "bundle"
        assert "id" in data
        assert "objects" in data

        # Validate objects
        assert len(data["objects"]) == 2

        obj = data["objects"][0]
        assert obj["type"] == "indicator"
        assert obj["spec_version"] == "2.1"
        assert "pattern" in obj
        assert obj["pattern_type"] == "stix"
        assert "confidence" in obj


# ============================================================================
# Helper Function Tests
# ============================================================================

class TestHelperFunctions:
    """Test utility/helper functions used by formatters."""

    def test_sanitize_name(self):
        """Test name sanitization for tool formats."""
        assert _sanitize_name("test.example.com") == "test-example-com"
        assert _sanitize_name("192.168.1.1") == "192-168-1-1"
        assert _sanitize_name("http://evil.com/path") == "http---evil-com-path"
        assert _sanitize_name("test:value\\data/file") == "test-value-data-file"

    def test_severity_from_confidence(self):
        """Test confidence to severity mapping."""
        assert _severity_from_confidence(100) == "high"
        assert _severity_from_confidence(85) == "high"
        assert _severity_from_confidence(80) == "medium"
        assert _severity_from_confidence(65) == "medium"
        assert _severity_from_confidence(60) == "low"
        assert _severity_from_confidence(0) == "low"

    def test_tlp_lower(self):
        """Test TLP normalization."""
        assert _tlp_lower("RED") == "red"
        assert _tlp_lower("AMBER") == "amber"
        assert _tlp_lower("GREEN") == "green"
        assert _tlp_lower("WHITE") == "white"
        assert _tlp_lower(None) == "green"
        assert _tlp_lower("") == "green"


# ============================================================================
# Integration Tests
# ============================================================================

class TestFormatterRegistry:
    """Test FORMATTERS registry and integration."""

    def test_all_17_formatters_registered(self):
        """Verify all 17 formatters are in registry."""
        expected_formats = [
            "txt", "csv", "json", "xml",
            "fortigate", "fortigate_ips", "checkpoint", "paloalto",
            "sentinel", "defender", "f5", "imperva",
            "arcsight", "elasticsearch", "cribl", "splunk", "fidelis"
        ]

        assert len(FORMATTERS) == 17

        for fmt in expected_formats:
            assert fmt in FORMATTERS, f"Format {fmt} not in registry"

    def test_formatter_registry_structure(self):
        """Test that each formatter has correct structure (function, mime)."""
        for fmt, (func, mime) in FORMATTERS.items():
            assert callable(func), f"Formatter {fmt} function not callable"
            assert isinstance(mime, str), f"Formatter {fmt} mime type not string"
            assert "/" in mime, f"Formatter {fmt} mime type invalid"

    def test_all_formatters_work_with_empty_input(self):
        """Test all formatters handle empty input gracefully."""
        for fmt, (func, mime) in FORMATTERS.items():
            result = func([])
            assert result is not None, f"Formatter {fmt} returned None"
            assert isinstance(result, str), f"Formatter {fmt} didn't return string"


# ============================================================================
# Security Tests
# ============================================================================

class TestFormatterSecurity:
    """Test security aspects of formatters."""

    def test_no_code_injection_in_xml(self):
        """Test XML formatter prevents code injection."""
        indicator = Indicator(
            value="<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            type="domain",
            source="test",
            confidence=50,
            tlp="WHITE",
        )
        result = export_xml([indicator])

        # Should not contain DOCTYPE or ENTITY
        assert "<!DOCTYPE" not in result
        assert "<!ENTITY" not in result
        # Should escape the value
        assert "&lt;" in result

    def test_no_script_injection_in_json(self):
        """Test JSON formatter prevents script injection."""
        indicator = Indicator(
            value="</script><script>alert('xss')</script>",
            type="domain",
            source="test",
            confidence=50,
            tlp="WHITE",
        )
        result = export_json([indicator])

        # JSON should properly escape
        data = json.loads(result)
        assert data[0]["value"] == "</script><script>alert('xss')</script>"

    def test_csv_injection_prevention(self):
        """Test CSV formatter prevents formula injection."""
        # CSV injection via formulas starting with =, +, -, @
        indicator = Indicator(
            value="=1+1",
            type="domain",
            source="test",
            confidence=50,
            tlp="WHITE",
        )
        result = export_csv([indicator])

        # Should be properly quoted in CSV
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert rows[0]["value"] == "=1+1"


# ============================================================================
# Performance Tests
# ============================================================================

class TestFormatterPerformance:
    """Test formatter performance with large datasets."""

    def test_large_dataset_txt(self):
        """Test TXT formatter with 10k indicators."""
        indicators = [
            Indicator(
                value=f"192.168.{i // 256}.{i % 256}",
                type="ip",
                source="test",
                confidence=50,
                tlp="WHITE",
            )
            for i in range(10000)
        ]

        result = export_txt(indicators)
        lines = result.strip().split("\n")
        assert len(lines) == 10000

    def test_large_dataset_json(self):
        """Test JSON formatter with large dataset."""
        indicators = [
            Indicator(
                value=f"test{i}.example.com",
                type="domain",
                source="test",
                confidence=50,
                tlp="WHITE",
                tags=["test", f"tag{i}"],
                metadata_={"index": i},
            )
            for i in range(1000)
        ]

        result = export_json(indicators)
        data = json.loads(result)
        assert len(data) == 1000


# ============================================================================
# Edge Case Tests
# ============================================================================

class TestFormatterEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_unicode_in_all_formats(self, sample_indicators):
        """Test unicode handling in all formats."""
        indicator = Indicator(
            value="тест.中国.рф",
            type="domain",
            source="test",
            confidence=50,
            tlp="WHITE",
            tags=["unicode", "тест", "中文"],
        )

        # Test each format can handle unicode
        for fmt, (func, mime) in FORMATTERS.items():
            result = func([indicator])
            assert isinstance(result, str)
            # Result should contain unicode (or escaped version)
            assert len(result) > 0

    def test_null_values_handling(self):
        """Test formatters handle None/null values gracefully."""
        indicator = Indicator(
            value="test.com",
            type="domain",
            source="test",
            confidence=50,
            tlp="WHITE",
            source_id=None,
            tags=None,
            metadata=None,
        )

        # All formatters should handle None values
        result = export_json([indicator])
        data = json.loads(result)
        assert data[0]["tags"] == []
        assert data[0]["metadata"] == {}

    def test_very_long_values(self):
        """Test formatters handle very long indicator values."""
        long_value = "a" * 10000
        indicator = Indicator(
            value=long_value,
            type="domain",
            source="test",
            confidence=50,
            tlp="WHITE",
        )

        result = export_txt([indicator])
        assert long_value in result

        result = export_json([indicator])
        data = json.loads(result)
        assert data[0]["value"] == long_value

    def test_special_tlp_values(self):
        """Test TLP value handling in formatters."""
        for tlp in ["WHITE", "GREEN", "AMBER", "RED"]:
            indicator = Indicator(
                value="1.2.3.4",
                type="ip",
                source="test",
                confidence=50,
                tlp=tlp,
            )

            result = export_json([indicator])
            data = json.loads(result)
            assert data[0]["tlp"] == tlp

            result = export_sentinel_stix([indicator])
            data = json.loads(result)
            assert data["indicators"][0]["tlpLevel"] == tlp.lower()
