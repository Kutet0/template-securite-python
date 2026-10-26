import sys

from tp2.utils.iocs import is_valid_ip, extract_strings, extract_iocs, find_flag, get_payload


def test_is_valid_ip():
    assert is_valid_ip("127.0.0.1")
    assert not is_valid_ip("999.1.1.1")


def test_extract_strings():
    result = extract_strings(b"\x00\x01hello world\x00ab")
    assert "hello world" in result
    assert "ab" not in result


def test_extract_iocs():
    data = extract_iocs(b"urlmon.dll\x00http://c2.example.test/gate.php\x00185.64.7.32\x00")
    assert data["domains"] == ["c2.example.test"]
    assert data["ips"] == ["185.64.7.32"]
    assert "urlmon.dll" not in data["domains"]


def test_find_flag_ignores_decoy():
    assert find_flag(b"FLAG=ESGI{vrai}\nflag is ESGI{decoy}") == "ESGI{vrai}"


def test_find_flag_absent():
    assert find_flag(b"rien") == ""


def test_get_payload_text_file(tmp_path):
    fichier = tmp_path / "note.txt"
    fichier.write_bytes(b"juste du texte")
    assert get_payload(str(fichier), b"juste du texte") == b"juste du texte"


def test_get_payload_overlay(tmp_path):
    data = open(sys.executable, "rb").read() + b"OVERLAY_MARKER"

    fichier = tmp_path / "fake.bin"
    fichier.write_bytes(data)

    payload = get_payload(str(fichier), data)

    assert payload.endswith(b"OVERLAY_MARKER")
    assert not payload.startswith(b"\x7fELF")
