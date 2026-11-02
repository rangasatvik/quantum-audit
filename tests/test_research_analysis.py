import csv

from research.analyze import analyze


def test_analysis_excludes_failures_and_retry_requests(tmp_path):
    source = tmp_path / "results.csv"
    rows = [
        {"host": "one.example", "category": "tech", "status": "ok", "group": "X25519MLKEM768", "hello_retry_request": "False", "tls_version": "TLSv1.3", "certificate_key_type": "EC", "overall_grade": "A"},
        {"host": "two.example", "category": "tech", "status": "ok", "group": "X25519", "hello_retry_request": "False", "tls_version": "TLSv1.3", "certificate_key_type": "RSA", "overall_grade": "B"},
        {"host": "three.example", "category": "tech", "status": "failed", "group": "", "hello_retry_request": "", "tls_version": "", "certificate_key_type": "", "overall_grade": ""},
        {"host": "four.example", "category": "tech", "status": "failed", "group": "X25519Kyber768Draft00", "hello_retry_request": "True", "tls_version": "", "certificate_key_type": "", "overall_grade": ""},
    ]
    with source.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    docs = tmp_path / "docs"
    findings = tmp_path / "findings.md"
    analyze(source, docs, findings)
    text = findings.read_text(encoding="utf-8")
    assert "1 of 2 sites with a measurable key exchange (50.0%)" in text
    assert "2 incomplete or failed" in text
    assert len(list(docs.glob("*.png"))) == 4
