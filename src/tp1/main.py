from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report
import argparse

def main():
    logger.info("Starting TP1")

    parser = argparse.ArgumentParser(description="IDS/IPS maison")
    parser.add_argument("--pcap")
    parser.add_argument("--iface")
    parser.add_argument("--out", default="report.json")

    args = parser.parse_args()

    logger.info(f"les arguments : {args}")

    capture = Capture(args.pcap, args.iface)
    capture.capture_traffic()
    capture.analyse("tcp")
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)

    report.save_json(args.out)

if __name__ == "__main__":
    main()