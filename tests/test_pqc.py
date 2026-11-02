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


def test_client_hello_offers_groups_and_real_key_shares():
    hello = pqc.client_hello("example.com")
    assert hello[:3] == bytes.fromhex("160301")
    assert int.from_bytes(hello[3:5], "big") == len(hello) - 5
    assert hello[5] == 1
    assert int.from_bytes(hello[6:9], "big") == len(hello) - 9
    body = hello[9:]
    offset = 35 + body[34]
    cipher_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2 + cipher_length
    offset += 1 + body[offset]
    extension_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    assert offset + extension_length == len(body)
    extensions = {}
    while offset < len(body):
        kind = int.from_bytes(body[offset:offset + 2], "big")
        size = int.from_bytes(body[offset + 2:offset + 4], "big")
        offset += 4
        extensions[kind] = body[offset:offset + size]
        offset += size
    assert extensions[10] == bytes.fromhex("000611ec001d6399")
    shares = extensions[51]
    assert int.from_bytes(shares[:2], "big") == len(shares) - 2
    assert shares[2:6] == bytes.fromhex("11ec04c0")
    assert shares[1222:1226] == bytes.fromhex("001d0020")
    assert len(shares[1226:]) == 32


def test_saved_server_hello():
    assert pqc.parse_server_hello(SERVER_HELLO) == {
        "group": "X25519", "hello_retry_request": False, "draft_requested": False, "draft_accepted": None}


def test_hybrid_server_hello():
    hybrid = SERVER_HELLO.replace(bytes.fromhex("00330006001d"), bytes.fromhex("0033000611ec"))
    assert pqc.parse_server_hello(hybrid)["group"] == "X25519MLKEM768"


def test_saved_retry_flags_draft():
    assert pqc.parse_server_hello(RETRY) == {
        "group": "X25519Kyber768Draft00", "hello_retry_request": True, "draft_requested": True, "draft_accepted": None}


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
    assert grade(tls, observation)["overall_grade"] == "B"
    tls["expiry"] = "2020-01-01T00:00:00+00:00"
    assert grade(tls, observation)["overall_grade"] == "F"
    assert grade(tls, observation)["next_step"] == "Renew the expired certificate."
    observation["host"] = "other.example"
    with pytest.raises(ValueError):
        grade(tls, observation)


def test_weak_certificate_recommendation():
    tls = {"host": "example.com", "certificate_key_type": "RSA", "certificate_key_size": 1024}
    observation = {"host": "example.com", "group": "X25519MLKEM768"}
    assert "weak certificate" in grade(tls, observation)["next_step"]
    assert grade(tls, observation)["overall_grade"] == "D"


def test_report_distinguishes_draft_request():
    tls = {"host": "example.com", "certificate_key_type": "EC", "certificate_key_size": 256}
    observation = {"host": "example.com", **pqc.parse_server_hello(RETRY)}
    assert "requested, not negotiated" in report(tls, observation)
    assert "acceptance unconfirmed" in report(tls, observation)
