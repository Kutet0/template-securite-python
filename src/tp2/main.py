import argparse
import os

from tp2.utils.config import logger
from tp2.utils.report import Report


def main():
    logger.info("Starting tp2")

    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", required=True, help="echantillon à analyser")
    parser.add_argument("--rules", required=True, help="rules")
    parser.add_argument("--out", required=True, help="dossier de sortie JSON")

    args = parser.parse_args()

    logger.info(f"les arguments : {args}")

    for name in os.listdir(args.samples):
        path = os.path.join(args.samples, name)
        if not os.path.isfile(path):
            continue
        report = Report(path)
        report.save_json(args.out)
        logger.info(f"rapport écrit pour {name}")


if __name__ == "__main__":
    main()
