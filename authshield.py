import argparse
import sys

from authshield.detector import detect_all
from authshield.parser import parse_auth_log
from authshield.reporter import build_report, render_terminal, write_json

def build_parser():
    parser = argparse.ArgumentParser(
        prog="authshield",
        description="Defensive authentication log analyzer and brute-force detector.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="Analyze an authentication CSV log.")
    analyze.add_argument("logfile", help="Path to CSV authentication log.")
    analyze.add_argument("--json", dest="json_path", help="Write findings to a JSON report.")
    return parser

def main():
    args = build_parser().parse_args()
    try:
        events = parse_auth_log(args.logfile)
        findings = detect_all(events)
        print(render_terminal(events, findings))
        if args.json_path:
            write_json(build_report(events, findings), args.json_path)
            print(f"\nReport saved   : {args.json_path}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"AuthShield error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
