"""Inspect the certificate and parameters of a single TLS connection."""

import socket
import ssl

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa, dsa


def scan(host, timeout=10):
    context = ssl.create_default_context(cafile=certifi.where())
    with socket.create_connection((host, 443), timeout=timeout) as connection:
        with context.wrap_socket(connection, server_hostname=host) as tls:
            certificate = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
            key = certificate.public_key()
            key_types = ((rsa.RSAPublicKey, "RSA"), (ec.EllipticCurvePublicKey, "EC"),
                         (dsa.DSAPublicKey, "DSA"), (ed25519.Ed25519PublicKey, "Ed25519"),
                         (ed448.Ed448PublicKey, "Ed448"))
            key_type = next((name for kind, name in key_types if isinstance(key, kind)), type(key).__name__)
            key_size = getattr(key, "key_size", {"Ed25519": 256, "Ed448": 456}.get(key_type))
            return {
                "host": host,
                "tls_version": tls.version(),
                "cipher_suite": tls.cipher()[0],
                "certificate_key_type": key_type,
                "certificate_key_size": key_size,
                "signature_algorithm": certificate.signature_algorithm_oid._name or certificate.signature_algorithm_oid.dotted_string,
                "issuer": certificate.issuer.rfc4514_string(),
                "expiry": certificate.not_valid_after_utc.isoformat(),
            }
