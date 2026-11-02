import csv

from research import scan_sites


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
