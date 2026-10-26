from tp2.utils.metadata import get_file_metadata, shannon_entropy


def test_shannon_entropy_two_symbols():
    """AABB : deux symboles équiprobables → 1 bit."""
    assert shannon_entropy(b"AABB") == 1.0


def test_shannon_entropy_empty():
    """Un contenu vide ne doit pas lever ZeroDivisionError."""
    assert shannon_entropy(b"") == 0.0


def test_get_file_metadata_hello():
    """Les empreintes et la taille de b'hello' sont connues."""
    meta = get_file_metadata(b"hello")
    assert meta["md5"] == "5d41402abc4b2a76b9719d911017c592"
    assert meta["size"] == 5
    assert meta["entropy"] == 1.92
