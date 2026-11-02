"""Inspect a single TLS ServerHello without finishing the handshake."""

import os
import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

HYBRID = 0x11EC
X25519 = 0x001D
DRAFT = 0x6399
HELLO_RETRY_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def vector(data, size=2):
    return len(data).to_bytes(size, "big") + data


def extension(kind, data):
    return kind.to_bytes(2, "big") + vector(data)


def client_hello(host):
    hostname = host.encode("idna")
    if not hostname or len(hostname) > 253:
        raise ValueError("invalid hostname")
    xkey = x25519.X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pqkey = mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shares = (HYBRID.to_bytes(2, "big") + vector(pqkey + xkey)
              + X25519.to_bytes(2, "big") + vector(xkey))
    extensions = b"".join([
        extension(0, vector(b"\x00" + vector(hostname))),
        extension(10, vector(b"\x11\xec\x00\x1d\x63\x99")),
        extension(13, vector(bytes.fromhex("08040805080604030503060308070808040105010601"))),
        extension(43, b"\x02\x03\x04"),
        extension(51, vector(shares)),
    ])
    body = (b"\x03\x03" + os.urandom(32) + vector(os.urandom(32), 1)
            + vector(bytes.fromhex("130113021303")) + b"\x01\x00" + vector(extensions))
    handshake = b"\x01" + vector(body, 3)
    return b"\x16\x03\x01" + vector(handshake)


def parse_server_hello(message):
    """Parse a complete handshake message (without TLS record headers)."""
    if len(message) < 4 or message[0] != 2 or int.from_bytes(message[1:4], "big") != len(message) - 4:
        raise ValueError("invalid ServerHello length or type")
    body = message[4:]
    if len(body) < 39:
        raise ValueError("truncated ServerHello")
    retry = body[2:34] == HELLO_RETRY_RANDOM
    offset = 35 + body[34]
    if offset + 5 > len(body):
        raise ValueError("truncated ServerHello fields")
    offset += 3
    extensions_length = int.from_bytes(body[offset:offset + 2], "big")
    offset += 2
    if offset + extensions_length != len(body):
        raise ValueError("invalid ServerHello extensions length")
    selected = None
    version = None
    seen = set()
    while offset < len(body):
        if offset + 4 > len(body):
            raise ValueError("truncated extension")
        kind = int.from_bytes(body[offset:offset + 2], "big")
        length = int.from_bytes(body[offset + 2:offset + 4], "big")
        offset += 4
        if offset + length > len(body) or kind in seen:
            raise ValueError("invalid ServerHello extension")
        seen.add(kind)
        data = body[offset:offset + length]
        offset += length
        if kind == 43:
            if len(data) != 2:
                raise ValueError("invalid selected version")
            version = int.from_bytes(data, "big")
        if kind == 51:
            if len(data) < 2 or (retry and len(data) != 2):
                raise ValueError("invalid key share")
            if not retry and (len(data) < 4 or int.from_bytes(data[2:4], "big") != len(data) - 4):
                raise ValueError("invalid key share length")
            selected = int.from_bytes(data[:2], "big")
    if version != 0x0304 or selected not in (HYBRID, X25519, DRAFT):
        raise ValueError("server did not select an offered TLS 1.3 group")
    if retry and selected != DRAFT:
        raise ValueError("server requested a key share already offered")
    if not retry and selected == DRAFT:
        raise ValueError("server selected a draft key share that was not sent")
    return {"group": {HYBRID: "X25519MLKEM768", X25519: "X25519", DRAFT: "X25519Kyber768Draft00"}[selected],
            "hello_retry_request": retry, "draft_requested": selected == DRAFT,
            "draft_accepted": None}


def _read_exact(connection, length):
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise ValueError("server closed connection before ServerHello")
        data.extend(chunk)
    return bytes(data)


def probe(host, timeout=10):
    hello = client_hello(host)
    with socket.create_connection((host, 443), timeout=timeout) as connection:
        connection.sendall(hello)
        message = bytearray()
        while len(message) < 4 or len(message) < 4 + int.from_bytes(message[1:4], "big"):
            header = _read_exact(connection, 5)
            size = int.from_bytes(header[3:5], "big")
            if header[0] != 22 or size == 0 or size > 16384:
                raise ValueError("server returned an alert or invalid TLS record")
            message.extend(_read_exact(connection, size))
            if len(message) > 65536:
                raise ValueError("ServerHello too large")
        length = 4 + int.from_bytes(message[1:4], "big")
        result = parse_server_hello(bytes(message[:length]))
        return {"host": host, **result}
