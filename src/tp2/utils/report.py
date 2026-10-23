import json
import os


class Report:
    def __init__(self, sample_path):
        self.sample_path = sample_path
        self.data = {
            "sha256": "",
            "md5": "",
            "size": 0,
            "entropy": 0.0,
            "file_type": "",
            "iocs": {
                "domains": [],
                "ips": [],
                "urls": [],
                "mutex": [],
                "registry": [],
            },
            "imports": [],
            "yara_matches": [],
            "family_guess": "",
            "mitre_attack": [],
            "llm_summary": "",
            "score": 0,
            "flag": "",
        }

    def save_json(self, out_dir) -> None:
        os.makedirs(out_dir, exist_ok=True)
        name = os.path.basename(self.sample_path)
        path = os.path.join(out_dir, f"{name}.json")
        with open(path, "w") as f:
            json.dump(self.data, f, indent=2)
