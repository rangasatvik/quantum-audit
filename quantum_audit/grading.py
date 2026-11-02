"""Grade separately collected TLS and key-exchange observations."""

from datetime import datetime, timezone

DEADLINE_NOTE = ("NIST IR 8547: RSA/ECC deprecated after 2030 and disallowed after 2035 "
                 "for applicable NIST-governed uses.")
TLS_LEGACY = "no PQ (TLS 1.2 only)"


def grade(tls, pqc):
    if tls.get("host") != pqc.get("host"):
        raise ValueError("TLS and key-exchange observations must have the same host")
    group = pqc.get("group")
    key_score = {"X25519MLKEM768": 100, "X25519": 70, "X25519Kyber768Draft00": 30}.get(group)
    version = tls.get("tls_version")
    cipher = tls.get("cipher_suite") or ""
    if group == TLS_LEGACY:
        if version not in ("TLSv1.2", "TLSv1.1", "TLSv1") or not cipher:
            raise ValueError("legacy classification requires a TLS version and cipher")
        key_score = 50 if version == "TLSv1.2" and cipher.startswith(("ECDHE-", "DHE-")) else 30
    key_type = tls.get("certificate_key_type")
    size = tls.get("certificate_key_size")
    if key_score is None or not isinstance(size, int) or key_type not in ("RSA", "EC", "DSA", "Ed25519", "Ed448"):
        raise ValueError("insufficient information to grade")
    cert_score = 70 if (key_type == "RSA" and size >= 2048) or (key_type == "EC" and size >= 256) or key_type in ("Ed25519", "Ed448") else 30
    expiry = tls.get("expiry")
    expired = False
    if expiry:
        expiry_date = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        if expiry_date.tzinfo is None:
            raise ValueError("certificate expiry must include a timezone")
        expired = expiry_date <= datetime.now(timezone.utc)
        if expired:
            cert_score = 0
    overall = round(key_score * 0.75 + cert_score * 0.25)
    if expired or (group == TLS_LEGACY and version in ("TLSv1", "TLSv1.1")):
        overall = 0
    elif cert_score < 70:
        overall = min(overall, 49)
    letter = "A" if overall >= 90 else "B" if overall >= 70 else "C" if overall >= 50 else "D" if overall >= 30 else "F"
    if expired:
        recommendation = "Renew the expired certificate."
    elif group == TLS_LEGACY:
        recommendation = "Enable TLS 1.3 with the X25519MLKEM768 hybrid key exchange."
    elif cert_score < 70:
        recommendation = "Replace the weak certificate key with a modern key."
    elif key_score == 100:
        recommendation = "Keep the hybrid key exchange enabled and monitor post-quantum certificate standards."
    else:
        recommendation = "Enable the standardized X25519MLKEM768 hybrid key exchange."
    return {"key_exchange_score": key_score, "certificate_score": cert_score,
            "overall_score": overall, "overall_grade": letter,
            "deadline_note": DEADLINE_NOTE, "next_step": recommendation}
