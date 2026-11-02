import argparse
import json
import ssl
import sys

from .scanner import scan
from .pqc import probe
from .report import report


def main():
    parser = argparse.ArgumentParser(prog="python -m quantum_audit")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="inspect a host's TLS connection")
    scan_parser.add_argument("host")
    scan_parser.add_argument("--json", action="store_true")
    probe_parser = commands.add_parser("probe", help="inspect one TLS ServerHello")
    probe_parser.add_argument("host")
    probe_parser.add_argument("--json", action="store_true")
    report_parser = commands.add_parser("report", help="combine saved scan and probe JSON files")
    report_parser.add_argument("tls_file")
    report_parser.add_argument("pqc_file")
    args = parser.parse_args()
    try:
        if args.command == "report":
            with open(args.tls_file, encoding="utf-8") as tls_file, open(args.pqc_file, encoding="utf-8") as pqc_file:
                print(report(json.load(tls_file), json.load(pqc_file)))
            return 0
        result = scan(args.host) if args.command == "scan" else probe(args.host)
    except (OSError, ssl.SSLError, ValueError, UnicodeError) as error:
        print(f"{args.command.capitalize()} failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result))
    else:
        for key, value in result.items():
            print(f"{key.replace('_', ' ').capitalize()}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
