import os, argparse
from tp2.utils.config import logger

def main():
    logger.info("Starting tp2")

    parser = argparse.ArgumentParser()
    parser.add_argument("--samples")
    parser.add_argument("--rules")
    parser.add_argument("--out")

    args = parser.parse_args()

    logger.info(f"les arguments : {args}")

if __name__ == "__main__":
    main()