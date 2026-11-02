import argparse
import json
import ssl
import sys

from .scanner import scan


def main():
    parser = argparse.ArgumentParser(prog="python -m quantum_audit")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="inspect a host's TLS connection")
    scan_parser.add_argument("host")
    scan_parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = scan(args.host)
    except (OSError, ssl.SSLError, ValueError, UnicodeError) as error:
        print(f"Scan failed for {args.host}: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result))
    else:
        for key, value in result.items():
            print(f"{key.replace('_', ' ').capitalize()}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
