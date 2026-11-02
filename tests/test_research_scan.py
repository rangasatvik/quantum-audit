import csv

from research import scan_sites
from quantum_audit.grading import TLS_LEGACY, grade


def test_scan_keeps_partial_results_and_pauses(monkeypatch):
    calls = []

    def probe(host, timeout):
        calls.append(("probe", host))
        raise OSError("probe unavailable")

    def scan(host, timeout):
        calls.append(("tls", host))
        return {"host": host, "tls_version": "TLSv1.3"}

    monkeypatch.setattr(scan_sites, "probe", probe)
    monkeypatch.setattr(scan_sites, "scan", scan)
    monkeypatch.setattr(scan_sites.time, "sleep", lambda duration: calls.append(("sleep", duration)))
    result = scan_sites.scan_host({"host": "example.com", "category": "tech", "source": "test"})
    assert calls == [("probe", "example.com"), ("sleep", 0.25), ("tls", "example.com")]
    assert result["status"] == "incomplete"
    assert result["pqc_error"] == "probe unavailable"
    assert result["tls_version"] == "TLSv1.3"


def test_tls12_protocol_alert_is_classified_and_graded(monkeypatch):
    def probe(host, timeout):
        raise ValueError("server returned an alert or invalid TLS record")

    def scan(host, timeout):
        return {"host": host, "tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
                "certificate_key_type": "RSA", "certificate_key_size": 2048}

    monkeypatch.setattr(scan_sites, "probe", probe)
    monkeypatch.setattr(scan_sites, "scan", scan)
    monkeypatch.setattr(scan_sites.time, "sleep", lambda duration: None)
    result = scan_sites.scan_host({"host": "example.com", "category": "tech", "source": "test"})
    assert result["status"] == "ok"
    assert result["group"] == TLS_LEGACY
    assert result["overall_grade"] == "C"
    assert "alert" in result["pqc_diagnostic"]
    assert not result.get("pqc_error")


def test_tls12_network_failure_is_not_classified():
    row = {"host": "example.com", "tls_version": "TLSv1.2", "pqc_error": "[Errno 54] Connection reset by peer"}
    assert "group" not in scan_sites.classify_legacy(row)


def test_tls12_without_forward_secrecy_grades_d():
    tls = {"host": "example.com", "tls_version": "TLSv1.2", "cipher_suite": "AES256-GCM-SHA384",
           "certificate_key_type": "RSA", "certificate_key_size": 2048}
    assert grade(tls, {"host": "example.com", "group": TLS_LEGACY})["overall_grade"] == "D"


def test_reclassify_saved_rows_preserves_timestamp_and_is_repeatable(tmp_path):
    output = tmp_path / "results.csv"
    output.write_text("timestamp,host,tls_version,cipher_suite,certificate_key_type,certificate_key_size,pqc_error\n"
                      "2026-01-01T00:00:00+00:00,example.com,TLSv1.2,ECDHE-RSA-AES256-GCM-SHA384,RSA,2048,server returned an alert or invalid TLS record\n", encoding="utf-8")
    scan_sites.reclassify(output)
    first = output.read_text(encoding="utf-8")
    scan_sites.reclassify(output)
    assert output.read_text(encoding="utf-8") == first
    with output.open(newline="", encoding="utf-8") as data:
        row = next(csv.DictReader(data))
    assert row["timestamp"] == "2026-01-01T00:00:00+00:00"
    assert row["overall_grade"] == "C"


def test_batch_delays_between_hosts_and_writes_rows(monkeypatch, tmp_path):
    sites = tmp_path / "sites.csv"
    sites.write_text("host,category,source\none.example,tech,test\ntwo.example,banks,test\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(scan_sites, "scan_host", lambda site, timeout: {**site, "status": "ok"})
    monkeypatch.setattr(scan_sites.time, "sleep", calls.append)
    output = tmp_path / "results.csv"
    scan_sites.run(sites, output)
    assert calls == [1]
    with output.open(newline="", encoding="utf-8") as data:
        assert [row["host"] for row in csv.DictReader(data)] == ["one.example", "two.example"]


def test_batch_continues_after_unexpected_host_error(monkeypatch, tmp_path):
    sites = tmp_path / "sites.csv"
    sites.write_text("host,category,source\none.example,tech,test\ntwo.example,banks,test\n", encoding="utf-8")

    def scan_host(site, timeout):
        if site["host"] == "one.example":
            raise RuntimeError("unexpected failure")
        return {**site, "status": "ok"}

    monkeypatch.setattr(scan_sites, "scan_host", scan_host)
    monkeypatch.setattr(scan_sites.time, "sleep", lambda duration: None)
    output = tmp_path / "results.csv"
    scan_sites.run(sites, output)
    with output.open(newline="", encoding="utf-8") as data:
        rows = list(csv.DictReader(data))
    assert rows[0]["status"] == "incomplete"
    assert "unexpected failure" in rows[0]["grading_error"]
    assert rows[1]["status"] == "ok"
