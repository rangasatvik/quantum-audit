import datetime
import json
import socket
import ssl
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from quantum_audit import scanner
from quantum_audit import __main__ as cli


def test_scan_uses_one_connection_and_extracts_certificate(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    connection = MagicMock()
    tls = MagicMock()
    tls.__enter__.return_value = tls
    tls.version.return_value = "TLSv1.3"
    tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    tls.getpeercert.return_value = cert.public_bytes(serialization.Encoding.DER)
    context = MagicMock()
    context.wrap_socket.return_value = tls
    connect = MagicMock(return_value=connection)
    connection.__enter__.return_value = connection
    monkeypatch.setattr(scanner.socket, "create_connection", connect)
    monkeypatch.setattr(scanner.ssl, "create_default_context", lambda **kwargs: context)
    result = scanner.scan("example.com")
    connect.assert_called_once_with(("example.com", 443), timeout=10)
    context.wrap_socket.assert_called_once_with(connection, server_hostname="example.com")
    assert result["certificate_key_type"] == "RSA"
    assert result["certificate_key_size"] == 2048
    assert result["issuer"] == "CN=Test CA"
    assert result["tls_version"] == "TLSv1.3"
    assert result["signature_algorithm"] == "sha256WithRSAEncryption"


def test_cli_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda host: {"host": host})
    monkeypatch.setattr("sys.argv", ["quantum_audit", "scan", "example.com", "--json"])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out) == {"host": "example.com"}


@pytest.mark.parametrize("error", [socket.timeout("timed out"), socket.gaierror("bad host"), ssl.SSLError("handshake failed")])
def test_cli_errors(monkeypatch, capsys, error):
    def fail(host):
        raise error
    monkeypatch.setattr(cli, "scan", fail)
    monkeypatch.setattr("sys.argv", ["quantum_audit", "scan", "example.com"])
    assert cli.main() == 1
    assert "Scan failed" in capsys.readouterr().err
