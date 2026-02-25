from app.query_parser import parse_kibana_query, Term

def test_kibana_query_parser_simple():
    rpn = parse_kibana_query("confidence:>70 AND type:ip")
    assert any(isinstance(t, Term) and t.field.lower() == 'confidence' and t.op == '>' and t.value == '70' for t in rpn)
    assert any(isinstance(t, Term) and t.field.lower() == 'type' and t.op == ':' and t.value.lower() == 'ip' for t in rpn)
    assert 'AND' in rpn
