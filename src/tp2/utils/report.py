import json
import os

from tp2.utils.config import logger
from tp2.utils.metadata import get_file_metadata


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

    def analyze(self):
        with open(self.sample_path, "rb") as f:
            data = f.read()
            self.data.update(get_file_metadata(data))
            logger.info(f"Analyse de : {self.sample_path}")

    def save_json(self, out_dir) -> None:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"{self.data['sha256']}.json")
        with open(path, "w") as f:
            json.dump(self.data, f, indent=2)
