import pytest

from quantum_audit import pqc
from quantum_audit.grading import grade
from quantum_audit.report import report


SERVER_HELLO = bytes.fromhex(
    "02000038 0303 " + "00" * 32 + " 00 1301 00 0010"
    " 002b00020304 00330006001d00020102"
)
RETRY = bytes.fromhex(
    "02000034 0303 cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
    " 00 1301 00 000c 002b00020304 003300026399"
)


def test_saved_server_hello():
    assert pqc.parse_server_hello(SERVER_HELLO) == {
        "group": "X25519", "hello_retry_request": False, "draft_accepted": None}


def test_hybrid_server_hello():
    hybrid = SERVER_HELLO.replace(bytes.fromhex("00330006001d"), bytes.fromhex("0033000611ec"))
    assert pqc.parse_server_hello(hybrid)["group"] == "X25519MLKEM768"


def test_saved_retry_flags_draft():
    assert pqc.parse_server_hello(RETRY) == {
        "group": "X25519Kyber768Draft00", "hello_retry_request": True, "draft_accepted": True}


@pytest.mark.parametrize("data", [SERVER_HELLO[:-1], SERVER_HELLO[:20], b"\x02\x00\x00\x00"])
def test_rejects_malformed_hello(data):
    with pytest.raises(ValueError):
        pqc.parse_server_hello(data)


def test_probe_fragmented_server_hello(monkeypatch):
    record = b"\x16\x03\x03" + len(SERVER_HELLO).to_bytes(2, "big") + SERVER_HELLO

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def sendall(self, data):
            assert data[:1] == b"\x16"

        def recv(self, length):
            nonlocal record
            data, record = record[:1], record[1:]
            return data

    calls = []
    def connect(address, timeout):
        calls.append((address, timeout))
        return Connection()
    monkeypatch.setattr(pqc.socket, "create_connection", connect)
    assert pqc.probe("example.com")["group"] == "X25519"
    assert calls == [(("example.com", 443), 10)]


def test_grading_and_report():
    tls = {"host": "example.com", "certificate_key_type": "EC", "certificate_key_size": 256}
    observation = {"host": "example.com", "group": "X25519MLKEM768", "draft_accepted": None}
    assert grade(tls, observation)["overall_grade"] == "A"
    assert "not determined" in report(tls, observation)
    observation["group"] = "X25519"
    assert grade(tls, observation)["overall_grade"] == "C"
    observation["host"] = "other.example"
    with pytest.raises(ValueError):
        grade(tls, observation)
