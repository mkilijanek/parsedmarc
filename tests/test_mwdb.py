"""Tests for app/services/mwdb.py — pure-logic functions."""
from __future__ import annotations


# ---------------------------------------------------------------------------
# _parse_dt
# ---------------------------------------------------------------------------

class TestParseDt:
    def _parse(self, s):
        from app.services.mwdb import _parse_dt
        return _parse_dt(s)

    def test_none_returns_none(self):
        assert self._parse(None) is None

    def test_empty_returns_none(self):
        assert self._parse("") is None

    def test_iso_with_Z(self):
        from datetime import timezone
        result = self._parse("2026-05-16T10:00:00Z")
        assert result is not None
        assert result.tzinfo == timezone.utc
        assert result.year == 2026

    def test_iso_with_offset(self):
        result = self._parse("2026-01-01T00:00:00+02:00")
        assert result is not None

    def test_invalid_returns_none(self):
        assert self._parse("not-a-date") is None


# ---------------------------------------------------------------------------
# _normalize_obj_tags
# ---------------------------------------------------------------------------

class TestNormalizeObjTags:
    def _norm(self, raw):
        from app.services.mwdb import _normalize_obj_tags
        return _normalize_obj_tags(raw)

    def test_none_returns_empty(self):
        assert self._norm(None) == []

    def test_empty_list_returns_empty(self):
        assert self._norm([]) == []

    def test_string_csv_split(self):
        result = self._norm("malware,trojan,rat")
        assert "malware" in result
        assert "trojan" in result
        assert "rat" in result

    def test_list_of_strings(self):
        result = self._norm(["a", "b", "c"])
        assert result == ["a", "b", "c"]

    def test_list_of_dicts_with_tag_key(self):
        result = self._norm([{"tag": "malware"}, {"tag": "c2"}])
        assert "malware" in result
        assert "c2" in result

    def test_dict_with_nested_tag(self):
        result = self._norm({"1": {"tag": "apt"}, "2": {"tag": "phishing"}})
        assert "apt" in result
        assert "phishing" in result

    def test_dict_with_string_values(self):
        result = self._norm({"a": "tag1", "b": "tag2"})
        assert "tag1" in result
        assert "tag2" in result

    def test_empty_tags_filtered(self):
        result = self._norm(["valid", "", "  "])
        assert result == ["valid"]


# ---------------------------------------------------------------------------
# _escape_lucene_value
# ---------------------------------------------------------------------------

class TestEscapeLuceneValue:
    def _esc(self, v):
        from app.services.mwdb import _escape_lucene_value
        return _escape_lucene_value(v)

    def test_plain_value_unchanged(self):
        assert self._esc("malware") == "malware"

    def test_double_quote_escaped(self):
        assert self._esc('say "hello"') == 'say \\"hello\\"'

    def test_backslash_escaped(self):
        assert self._esc("a\\b") == "a\\\\b"


# ---------------------------------------------------------------------------
# _tag_term
# ---------------------------------------------------------------------------

class TestTagTerm:
    def _term(self, tag):
        from app.services.mwdb import _tag_term
        return _tag_term(tag)

    def test_simple_tag(self):
        assert self._term("malware") == "tag:malware"

    def test_tag_with_colon_quoted(self):
        result = self._term("feed:vx")
        assert result == 'tag:"feed:vx"'

    def test_tag_with_space_quoted(self):
        result = self._term("bad actor")
        assert '"' in result

    def test_empty_tag_returns_empty(self):
        assert self._term("") == ""


# ---------------------------------------------------------------------------
# _build_tag_query
# ---------------------------------------------------------------------------

class TestBuildTagQuery:
    def _build(self, tags):
        from app.services.mwdb import _build_tag_query
        return _build_tag_query(tags)

    def test_single_tag_no_parens(self):
        result = self._build(["malware"])
        assert result == "tag:malware"

    def test_multiple_tags_joined_with_or(self):
        result = self._build(["malware", "c2"])
        assert "OR" in result
        assert "tag:malware" in result
        assert "tag:c2" in result

    def test_empty_list_raises(self):
        import pytest
        with pytest.raises(ValueError):
            self._build([])

    def test_empty_string_tags_skipped(self):
        import pytest
        with pytest.raises(ValueError):
            self._build(["", "  "])


# ---------------------------------------------------------------------------
# _build_object_query
# ---------------------------------------------------------------------------

class TestBuildObjectQuery:
    def _build(self, tags, custom=""):
        from app.services.mwdb import _build_object_query
        return _build_object_query(tags, custom)

    def test_tags_only(self):
        result = self._build(["malware"])
        assert "tag:malware" in result

    def test_custom_filter_only(self):
        result = self._build([], "type:file")
        assert result == "type:file"

    def test_tags_and_custom_combined(self):
        result = self._build(["malware"], "type:file")
        assert "AND" in result
        assert "malware" in result
        assert "type:file" in result

    def test_both_empty_returns_empty(self):
        assert self._build([], "") == ""


# ---------------------------------------------------------------------------
# _parse_org_list
# ---------------------------------------------------------------------------

class TestParseOrgList:
    def _parse(self, raw):
        from app.services.mwdb import _parse_org_list
        return _parse_org_list(raw)

    def test_none_returns_empty(self):
        assert self._parse(None) == []

    def test_empty_returns_empty(self):
        assert self._parse("") == []

    def test_single_org(self):
        assert self._parse("CERT-PL") == ["CERT-PL"]

    def test_multiple_orgs(self):
        result = self._parse("CERT-PL,NCSC,TeamT5")
        assert len(result) == 3
        assert "CERT-PL" in result

    def test_duplicates_removed(self):
        result = self._parse("cert,CERT,cert")
        assert len(result) == 1

    def test_whitespace_stripped(self):
        result = self._parse("  CERT  ,  NCSC  ")
        assert "CERT" in result
        assert "NCSC" in result


# ---------------------------------------------------------------------------
# _object_matches_organizations
# ---------------------------------------------------------------------------

class TestObjectMatchesOrganizations:
    def _match(self, obj, orgs):
        from app.services.mwdb import _object_matches_organizations
        return _object_matches_organizations(obj, orgs)

    def test_empty_orgs_always_matches(self):
        assert self._match({"organization": "anyone"}, []) is True

    def test_matches_organization_field(self):
        assert self._match({"organization": "CERT-PL"}, ["cert-pl"]) is True

    def test_no_match_returns_false(self):
        assert self._match({"organization": "OtherOrg"}, ["CERT-PL"]) is False

    def test_matches_uploader_list_string(self):
        assert self._match({"uploaders": ["CERT-PL", "NCSC"]}, ["NCSC"]) is True

    def test_matches_uploader_dict_org_key(self):
        obj = {"uploaders": [{"organization": "TeamT5"}]}
        assert self._match(obj, ["teamt5"]) is True

    def test_case_insensitive(self):
        assert self._match({"organization": "CeRt-PL"}, ["cert-pl"]) is True


# ---------------------------------------------------------------------------
# _object_matches_group
# ---------------------------------------------------------------------------

class TestObjectMatchesGroup:
    def _match(self, obj, group):
        from app.services.mwdb import _object_matches_group
        return _object_matches_group(obj, group)

    def test_empty_group_returns_false(self):
        assert self._match({}, "") is False

    def test_none_group_returns_false(self):
        assert self._match({}, None) is False

    def test_matches_uploader_string(self):
        assert self._match({"uploaders": ["my-group"]}, "my-group") is True

    def test_matches_uploader_dict_group_key(self):
        assert self._match({"uploaders": [{"group": "cert"}]}, "cert") is True

    def test_no_match_returns_false(self):
        assert self._match({"uploaders": ["other"]}, "my-group") is False

    def test_matches_top_level_organization(self):
        assert self._match({"organization": "cert"}, "cert") is True

    def test_case_insensitive(self):
        assert self._match({"uploaders": ["MyGroup"]}, "mygroup") is True


# ---------------------------------------------------------------------------
# _parse_tag_list
# ---------------------------------------------------------------------------

class TestParseTagList:
    def _parse(self, raw):
        from app.services.mwdb import _parse_tag_list
        return _parse_tag_list(raw)

    def test_none_returns_empty(self):
        assert self._parse(None) == []

    def test_empty_returns_empty(self):
        assert self._parse("") == []

    def test_single_tag(self):
        assert self._parse("malware") == ["malware"]

    def test_multiple_tags(self):
        result = self._parse("malware,c2,rat")
        assert len(result) == 3

    def test_duplicates_removed(self):
        result = self._parse("malware,MALWARE,malware")
        assert len(result) == 1

    def test_whitespace_stripped(self):
        result = self._parse("  malware  ,  c2  ")
        assert "malware" in result
        assert "c2" in result

    def test_empty_parts_skipped(self):
        result = self._parse("malware,,c2")
        assert len(result) == 2
