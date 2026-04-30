from __future__ import annotations

from datetime import datetime, timezone

from app.adapters import AdapterCapabilities, CanonicalIOC, FetchBatch, build_feed_registry
from app.adapters.pipeline import persist_batches
from app.config import Config
from app.runtime_env import clear_runtime_env_overrides, push_runtime_env_overrides, update_proxy_settings_from_mapping
from app.services.common import build_feed_session
from app.models import FeedStats, Indicator


class FakeAdapter:
    source_type = "fake"
    capabilities = AdapterCapabilities(supports_tags=True, supported_ioc_types=("ip",))

    def fetch_batches(self) -> list[FetchBatch]:
        return [
            FetchBatch(
                source="fake",
                items=(
                    CanonicalIOC(
                        value="198.51.100.10",
                        ioc_type="ip",
                        source_ref="fake-ref",
                        first_seen=datetime(2026, 4, 21, 12, 0, 0, tzinfo=timezone.utc),
                        last_seen=datetime(2026, 4, 21, 12, 0, 0, tzinfo=timezone.utc),
                        confidence=77,
                        tlp="AMBER",
                        tags=("test",),
                        metadata={"origin": "fake"},
                    ),
                ),
                metadata={"mode": "contract-test"},
            )
        ]

    def execute(self) -> dict[str, object]:
        return {"fetched": 1, "deactivated": 0, "errors": 0, "details": {"adapter": "fake"}}


def test_runtime_overrides_feed_config_values():
    clear_runtime_env_overrides()
    with push_runtime_env_overrides({"MWDB_URL": "https://runtime.example", "MWDB_TAGS": "apt,malware"}):
        cfg = Config()
        assert cfg.MWDB_URL == "https://runtime.example"
        assert cfg.MWDB_TAGS == "apt,malware"
    clear_runtime_env_overrides()


def test_build_feed_session_uses_runtime_proxy_settings():
    update_proxy_settings_from_mapping(
        {
            "proxy.http_url": "http://proxy.local:8080",
            "proxy.https_url": "http://proxy.local:8443",
            "proxy.no_proxy": "localhost,127.0.0.1",
            "proxy.ca_bundle_path": "/tmp/ca.pem",
            "proxy.skip_tls_verify": "0",
        }
    )
    with build_feed_session(source="mwdb") as session:
        assert session.runtime_proxies["http"] == "http://proxy.local:8080"
        assert session.runtime_proxies["https"] == "http://proxy.local:8443"
        assert session.runtime_no_proxy == "localhost,127.0.0.1"
        assert session.runtime_verify == "/tmp/ca.pem"


def test_runtime_session_request_verify_override_takes_precedence():
    update_proxy_settings_from_mapping(
        {
            "proxy.ca_bundle_path": "/tmp/ca.pem",
            "proxy.skip_tls_verify": "0",
        }
    )
    with build_feed_session(source="misp") as session:
        merged = session.merge_environment_settings(
            "https://misp.example.invalid",
            proxies={},
            stream=False,
            verify=False,
            cert=None,
        )
        assert merged["verify"] is False


def test_feed_registry_contains_core_sources():
    registry = build_feed_registry()
    assert set(registry.keys()) == {"crowdsec", "misp", "malwarebazaar", "mwdb", "abusech"}
    adapter = registry.get("mwdb")
    assert adapter.source_type == "mwdb"
    assert adapter.capabilities.supports_custom_filter is True


def test_fake_adapter_contract_shape():
    adapter = FakeAdapter()
    assert adapter.source_type == "fake"
    assert adapter.capabilities.supported_ioc_types == ("ip",)
    batches = adapter.fetch_batches()
    assert len(batches) == 1
    assert batches[0].source == "fake"
    assert batches[0].items[0].value == "198.51.100.10"
    result = adapter.execute()
    assert result["fetched"] == 1


def test_persist_batches_writes_indicators_and_feed_stats(test_db):
    batch = FetchBatch(
        source="adaptertest",
        items=(
            CanonicalIOC(
                value="example.invalid",
                ioc_type="domain",
                source_ref="row-1",
                first_seen=datetime(2026, 4, 21, 13, 0, 0, tzinfo=timezone.utc),
                last_seen=datetime(2026, 4, 21, 13, 0, 0, tzinfo=timezone.utc),
                confidence=66,
                tlp="GREEN",
                tags=("tag-a",),
                metadata={"sample": True},
            ),
        ),
        metadata={"reason": "pipeline-test"},
    )
    results = persist_batches(test_db, [batch], now=datetime(2026, 4, 21, 13, 0, 0, tzinfo=timezone.utc))
    test_db.commit()

    row = test_db.query(Indicator).filter(Indicator.source == "adaptertest").one()
    stats = test_db.query(FeedStats).filter(FeedStats.source == "adaptertest").one()

    assert results["adaptertest"]["fetched"] == 1
    assert row.value == "example.invalid"
    assert row.metadata_["adaptertest"]["sample"] is True
    assert stats.metadata_["reason"] == "pipeline-test"
