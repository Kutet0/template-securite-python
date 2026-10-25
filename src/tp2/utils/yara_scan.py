import os
import yara
from tp2.utils.config import logger


def load_rules(rules_dir: str) -> list:
    if not os.path.isdir(rules_dir):
        logger.warning(f"rule dir {rules_dir} is not a directory")
        return []
    compiled = []
    for rule_file in os.listdir(rules_dir):
        path = os.path.join(rules_dir, rule_file)
        if not os.path.isfile(path):
            continue
        try:
            compiled.append(yara.compile(filepath=path))
        except yara.Error:
            logger.warning(f"Règle ignorée : {rule_file}")
            continue
    return compiled


def yara_scan(data: bytes, rules: list) -> list[str]:
    yara_rules = []
    for rule in rules:
        for match in rule.match(data=data):
            yara_rules.append(match.rule)
    return sorted(set(yara_rules))
