"""Produce charts and a plain-language summary from a study CSV."""

import argparse
import csv
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parent.parent


def chart(labels, values, title, ylabel, destination, maximum=None):
    figure, axis = plt.subplots(figsize=(9, 5))
    bars = axis.bar(labels, values, color="#335c81")
    axis.set_title(title)
    axis.set_ylabel(ylabel)
    if maximum is not None:
        axis.set_ylim(0, maximum * 1.12)
        axis.set_yticks(range(0, maximum + 1, 20))
    axis.bar_label(bars, padding=3, fmt="%.1f" if maximum else "%d")
    axis.tick_params(axis="x", labelrotation=30)
    figure.tight_layout()
    figure.savefig(destination, dpi=150)
    plt.close(figure)


def analyze(input_path, docs_path, findings_path):
    with input_path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    docs_path.mkdir(parents=True, exist_ok=True)
    pq_rows = [row for row in rows if row.get("group") in ("X25519MLKEM768", "X25519", "X25519Kyber768Draft00") and row.get("hello_retry_request") != "True"]
    categories = {row["category"]: [] for row in rows}
    for row in pq_rows:
        categories[row["category"]].append(row)
    hybrid = sum(row["group"] == "X25519MLKEM768" for row in pq_rows)
    labels = ["Overall"] + sorted(categories)
    percentages = [100 * hybrid / len(pq_rows) if pq_rows else 0]
    percentages += [100 * sum(row["group"] == "X25519MLKEM768" for row in categories[label]) / len(categories[label]) if categories[label] else 0 for label in labels[1:]]
    if pq_rows:
        measured = [(label, value) for label, value in zip(labels, percentages) if label == "Overall" or categories[label]]
        chart([item[0] for item in measured], [item[1] for item in measured], "Hybrid PQ key exchange among measured sites", "Sites (%)", docs_path / "pqc_adoption.png", 100)
    else:
        figure, axis = plt.subplots(figsize=(9, 5))
        axis.text(0.5, 0.5, "No measurable key exchanges", ha="center", va="center")
        axis.set_axis_off()
        figure.savefig(docs_path / "pqc_adoption.png", dpi=150)
        plt.close(figure)
    for field, title, filename in (("overall_grade", "Overall grades", "grade_distribution.png"),
                                    ("tls_version", "TLS versions", "tls_versions.png"),
                                    ("certificate_key_type", "Certificate key types", "certificate_keys.png")):
        counts = Counter(row[field] for row in rows if row.get(field))
        chart(sorted(counts), [counts[label] for label in sorted(counts)], title, "Sites", docs_path / filename)
    successful = sum(row.get("status") == "ok" for row in rows)
    failures = len(rows) - successful
    pq_summary = (f"The hybrid X25519MLKEM768 group was selected by {hybrid} of {len(pq_rows)} sites with a measurable key exchange ({percentages[0]:.1f}%)."
                  if pq_rows else "No sites had a measurable key exchange; an adoption percentage cannot be calculated.")
    lines = ["# Research findings", "", f"The study contains {len(rows)} sites: {successful} complete results and {failures} incomplete or failed results.",
             pq_summary,
             "", "## By category", ""]
    for label, percentage in zip(labels[1:], percentages[1:]):
        count = len(categories[label])
        selected = sum(row["group"] == "X25519MLKEM768" for row in categories[label])
        lines.append(f"- {label}: {selected} of {count} measured sites ({percentage:.1f}%)." if count else f"- {label}: no measurable sites.")
    lines += ["", "## Other observations", ""]
    for field, label in (("overall_grade", "Grades"), ("tls_version", "TLS versions"), ("certificate_key_type", "Certificate keys")):
        counts = Counter(row[field] for row in rows if row.get(field))
        summary = ", ".join(f"{name}: {count}" for name, count in sorted(counts.items())) or "none measured"
        lines.append(f"- {label} ({sum(counts.values())} measured): {summary}.")
    pq_failures = sum(bool(row.get("pqc_error")) for row in rows)
    tls_failures = sum(bool(row.get("tls_error")) for row in rows)
    retries = sum(row.get("hello_retry_request") == "True" for row in rows)
    lines.append(f"- Incomplete measurements: {pq_failures} PQ probe errors, {tls_failures} certificate scan errors, and {retries} retry requests. These counts can overlap.")
    timestamps = sorted(row["timestamp"] for row in rows if row.get("timestamp"))
    if timestamps:
        lines.extend(["", f"Observations were collected from {timestamps[0]} to {timestamps[-1]} (UTC)."])
    lines += ["", "[Cloudflare](https://blog.cloudflare.com/post-quantum-visibility/) reported about 15% adoption on connections to origin servers; this study measures public-facing hosts, so the populations and methods differ and the percentages are not directly comparable.",
              "", "Grades use the project's heuristic: 75% key-exchange score and 25% certificate score, with caps for weak or expired keys. They are not a comprehensive security assessment.",
              "", "The ranked entries come from [Tranco list V354N](https://tranco-list.eu/list/V354N) (retrieved 2026-11-02); other entries were hand-picked. This is a small, non-random sample, not a representative estimate of all websites. Each host receives a raw PQ probe and a separate certificate handshake, paused between, with at least one second between hosts. The connections may reach different endpoints. A non-selected group may still be supported. The probe offers only TLS 1.3; a failed probe does not establish why negotiation failed. Failed and retry-request probes are excluded from the PQ percentage, not counted as negative results. The raw ServerHello is not authenticated; certificate verification failures are recorded separately.",
              "", "Reproduce the study with `python research/scan_sites.py --timeout 5`, then `python research/analyze.py`. The scan overwrites `research/results.csv` and saves each row as it finishes.", ""]
    findings_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "research/results.csv")
    parser.add_argument("--docs", type=Path, default=ROOT / "docs")
    parser.add_argument("--findings", type=Path, default=ROOT / "research/FINDINGS.md")
    arguments = parser.parse_args()
    analyze(arguments.input, arguments.docs, arguments.findings)


if __name__ == "__main__":
    main()
