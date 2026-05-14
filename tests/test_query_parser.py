from __future__ import annotations

import pytest

from app.query_parser import parse_kibana_query, Term

def test_kibana_query_parser_simple():
    rpn = parse_kibana_query("confidence:>70 AND type:ip")
    assert any(isinstance(t, Term) and t.field.lower() == 'confidence' and t.op == '>' and t.value == '70' for t in rpn)
    assert any(isinstance(t, Term) and t.field.lower() == 'type' and t.op == ':' and t.value.lower() == 'ip' for t in rpn)
    assert 'AND' in rpn


# ---------------------------------------------------------------------------
# TestQueryParserEdgeCases — migrated from test_coverage_boost.py
# ---------------------------------------------------------------------------

class TestQueryParserEdgeCases:

    def test_parse_empty_string(self):
        result = parse_kibana_query("")
        assert result == [] or result is None or result == ()

    def test_parse_simple_term_raises_without_field(self):
        # A bare term without "field:value" format is an incomplete predicate
        with pytest.raises(ValueError):
            parse_kibana_query("test")

    def test_parse_field_value(self):
        result = parse_kibana_query("type:ip")
        assert result is not None

    def test_parse_boolean_and(self):
        result = parse_kibana_query("type:ip AND confidence:>80")
        assert result is not None

    def test_parse_boolean_or(self):
        result = parse_kibana_query("type:ip OR type:domain")
        assert result is not None

    def test_parse_boolean_not(self):
        result = parse_kibana_query("NOT type:ip")
        assert result is not None

    def test_parse_greater_than_operator(self):
        result = parse_kibana_query("confidence:>70")
        assert result is not None

    def test_parse_less_than_operator(self):
        result = parse_kibana_query("confidence:<50")
        assert result is not None

    def test_parse_parentheses(self):
        result = parse_kibana_query("(type:ip OR type:domain) AND confidence:>70")
        assert result is not None

    def test_parse_quoted_value(self):
        result = parse_kibana_query('tags:"apt malware"')
        assert result is not None

    def test_parse_wildcard(self):
        result = parse_kibana_query("value:1.2.3.*")
        assert result is not None
