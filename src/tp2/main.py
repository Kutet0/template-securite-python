import argparse
from tp2.utils.config import logger


def main():
    logger.info("Starting tp2")

    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", required=True, help="samples")
    parser.add_argument("--rules", required=True, help="rules")
    parser.add_argument("--out", required=True, help="out")

    args = parser.parse_args()

    logger.info(f"les arguments : {args}")


if __name__ == "__main__":
    main()
