import json

from tp2.utils.report import Report


def test_report_init_keys():
    report = Report("x")
    expected = {
        "sha256",
        "md5",
        "size",
        "entropy",
        "file_type",
        "iocs",
        "imports",
        "yara_matches",
        "family_guess",
        "mitre_attack",
        "llm_summary",
        "score",
        "flag",
    }

    assert set(report.data.keys()) == expected


def test_write_json(tmp_path):
    report = Report("x")
    chemin = tmp_path / "a.json"
    report._write_json(str(chemin))

    with open(chemin) as f:
        relu = json.load(f)

    assert relu == report.data


def test_save_json(tmp_path):
    report = Report("x")
    report.data["sha256"] = "abc"
    out = tmp_path / "out"
    report.save_json(str(out))

    assert (out / "abc.json").exists()
    assert (out / "x.triage.json").exists()


def test_analyze(tmp_path):
    fichier = tmp_path / "sample.txt"
    fichier.write_bytes(b"FLAG=ESGI{t}")
    report = Report(str(fichier))
    report.analyze([])

    assert report.data["size"] == 12
    assert report.data["flag"] == "ESGI{t}"
