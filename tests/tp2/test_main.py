import sys

from tp2.main import main


def test_main_writes_reports(tmp_path, monkeypatch):
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "s.txt").write_bytes(b"http://c2.example.test/gate.php")

    out = tmp_path / "out"

    monkeypatch.setattr(
        sys,
        "argv",
        ["tp2", "--samples", str(samples), "--rules", str(tmp_path / "norules"), "--out", str(out)],
    )
    main()

    assert (out / "s.txt.triage.json").exists()
