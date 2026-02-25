from app.services.misp import extract_tlp_from_tags

def test_misp_tlp_extraction_attribute_priority():
    assert extract_tlp_from_tags(['tlp:red','apt28'], ['tlp:green']) == 'RED'

def test_misp_tlp_default_green():
    assert extract_tlp_from_tags(['apt','malware'], ['foo']) == 'GREEN'

def test_misp_tlp_clear_maps_to_white():
    assert extract_tlp_from_tags(['tlp:clear'], []) == 'WHITE'
