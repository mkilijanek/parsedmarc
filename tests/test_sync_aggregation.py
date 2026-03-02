from __future__ import annotations

from app.main import _aggregate_fetched_count


def test_aggregate_fetched_count_flat_dict():
    assert _aggregate_fetched_count({"fetched": 5, "deactivated": 1}) == 5


def test_aggregate_fetched_count_nested_dict():
    payload = {"abusech": {"fetched": 3}, "bazaar": {"fetched": 2}, "meta": {"x": 1}}
    assert _aggregate_fetched_count(payload) == 5


def test_aggregate_fetched_count_deeply_nested_dict():
    payload = {
        "abusech": {
            "threatfox": {"fetched": 4},
            "urlhaus": {"fetched": 3},
            "yaraify": {"fetched": 2},
        },
        "bazaar": {"fetched": 1},
    }
    assert _aggregate_fetched_count(payload) == 10


def test_aggregate_fetched_count_prefers_parent_summary_to_avoid_double_count():
    payload = {
        "abusech": {
            "fetched": 7,
            "threatfox": {"fetched": 4},
            "urlhaus": {"fetched": 3},
        }
    }
    assert _aggregate_fetched_count(payload) == 7
