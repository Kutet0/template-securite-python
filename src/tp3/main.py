import argparse

from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    logger.info("Starting TP3")

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=str, required=True, help="Target URL")
    args = parser.parse_args()

    logger.info(f"Target : {args.target}")

    ip = args.target
    challenges = {"1": f"http://{ip}/captcha1/", "2": f"http://{ip}/captcha2/"}

    for i in challenges:
        url = challenges[i]
        session = Session(url)
        session.prepare_request()
        session.submit_request()

        while not session.process_response():
            session.prepare_request()
            session.submit_request()

        logger.info("Smell good !")
        logger.info(f"Flag for {url} : {session.get_flag()}")


if __name__ == "__main__":
    main()
