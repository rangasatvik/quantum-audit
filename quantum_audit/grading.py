"""Grade separately collected TLS and key-exchange observations."""

DEADLINE_NOTE = ("NIST IR 8547: RSA/ECC deprecated after 2030 and disallowed after 2035 "
                 "for applicable NIST-governed uses.")


def grade(tls, pqc):
    if tls.get("host") != pqc.get("host"):
        raise ValueError("TLS and key-exchange observations must have the same host")
    group = pqc.get("group")
    key_score = {"X25519MLKEM768": 100, "X25519": 60, "X25519Kyber768Draft00": 30}.get(group)
    key_type = tls.get("certificate_key_type")
    size = tls.get("certificate_key_size")
    if key_score is None or not isinstance(size, int) or key_type not in ("RSA", "EC", "DSA", "Ed25519", "Ed448"):
        raise ValueError("insufficient information to grade")
    cert_score = 70 if (key_type == "RSA" and size >= 2048) or (key_type == "EC" and size >= 256) or key_type in ("Ed25519", "Ed448") else 30
    overall = round(key_score * 0.75 + cert_score * 0.25)
    letter = "A" if overall >= 90 else "B" if overall >= 70 else "C" if overall >= 50 else "D" if overall >= 30 else "F"
    recommendation = ("Keep the hybrid key exchange enabled and monitor post-quantum certificate standards."
                      if key_score == 100 else "Enable the standardized X25519MLKEM768 hybrid key exchange.")
    return {"key_exchange_score": key_score, "certificate_score": cert_score,
            "overall_score": overall, "overall_grade": letter,
            "deadline_note": DEADLINE_NOTE, "next_step": recommendation}
