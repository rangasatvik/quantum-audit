"""Scan each listed host sequentially, recording partial results and errors."""

import argparse
import csv
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from quantum_audit.grading import grade
from quantum_audit.pqc import probe
from quantum_audit.scanner import scan

FIELDS = ["timestamp", "host", "category", "source", "status", "tls_error", "pqc_error", "grading_error",
          "tls_version", "cipher_suite", "certificate_key_type", "certificate_key_size", "signature_algorithm",
          "issuer", "expiry", "group", "hello_retry_request", "draft_requested", "draft_accepted",
          "key_exchange_score", "certificate_score", "overall_score", "overall_grade", "next_step"]


def scan_host(site, timeout=10):
    host = site["host"]
    row = {**site, "timestamp": datetime.now(timezone.utc).isoformat()}
    tls = None
    pqc = None
    try:
        pqc = probe(host, timeout=timeout)
        row.update(pqc)
    except (OSError, ValueError, UnicodeError) as error:
        row["pqc_error"] = str(error)
    time.sleep(0.25)
    try:
        tls = scan(host, timeout=timeout)
        row.update(tls)
    except (OSError, ValueError, UnicodeError) as error:
        row["tls_error"] = str(error)
    if tls is not None and pqc is not None and not pqc["hello_retry_request"]:
        try:
            row.update(grade(tls, pqc))
        except (ValueError, KeyError, TypeError) as error:
            row["grading_error"] = str(error)
    elif pqc is not None and pqc["hello_retry_request"]:
        row["grading_error"] = "Key exchange was requested but not negotiated"
    row["status"] = "ok" if row.get("overall_grade") else "incomplete"
    return row


def run(sites_path, output_path, timeout=10):
    with sites_path.open(newline="", encoding="utf-8") as source:
        sites = list(csv.DictReader(source))
    hosts = [site["host"].lower() for site in sites]
    if len(hosts) != len(set(hosts)):
        raise ValueError("site list contains duplicate hosts")
    with output_path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for index, site in enumerate(sites):
            if index:
                time.sleep(1)
            try:
                row = scan_host(site, timeout)
            except Exception as error:
                row = {**site, "timestamp": datetime.now(timezone.utc).isoformat(),
                       "status": "incomplete", "grading_error": f"{type(error).__name__}: {error}"}
            writer.writerow(row)
            output.flush()
            print(f"{index + 1}/{len(sites)} {site['host']}: {row['status']}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sites", type=Path, default=ROOT / "research/sites.txt")
    parser.add_argument("--output", type=Path, default=ROOT / "research/results.csv")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    run(args.sites, args.output, args.timeout)


if __name__ == "__main__":
    main()
