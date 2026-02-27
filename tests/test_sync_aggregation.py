from __future__ import annotations

from app.main import _aggregate_fetched_count


def test_aggregate_fetched_count_flat_dict():
    assert _aggregate_fetched_count({"fetched": 5, "deactivated": 1}) == 5


def test_aggregate_fetched_count_nested_dict():
    payload = {"abusech": {"fetched": 3}, "bazaar": {"fetched": 2}, "meta": {"x": 1}}
    assert _aggregate_fetched_count(payload) == 5

