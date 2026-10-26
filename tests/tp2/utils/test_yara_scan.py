from tp2.utils.yara_scan import load_rules, yara_scan


def test_load_rules_missing_dir():
    assert load_rules("") == []


def test_load_rules_and_scan(tmp_path):
    (tmp_path / "test.yar").write_text('rule Regle_Test { strings: $a = "MOT_SECRET" condition: $a }')
    rules = load_rules(str(tmp_path))

    assert len(rules) == 1
    assert yara_scan(b"..MOT_SECRET..", rules) == ["Regle_Test"]


def test_yara_scan_no_match(tmp_path):
    (tmp_path / "test.yar").write_text('rule Regle_Test { strings: $a = "MOT_SECRET" condition: $a }')
    rules = load_rules(str(tmp_path))

    assert yara_scan(b"rien", rules) == []
