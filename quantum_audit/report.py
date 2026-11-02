"""Render a combined report from separately collected observations."""

from .grading import grade


def report(tls, pqc):
    scores = grade(tls, pqc)
    lines = [f"TLS report: {tls['host']}"]
    for label, value in (("TLS version", tls.get("tls_version")), ("Cipher suite", tls.get("cipher_suite")),
                         ("Certificate key", f"{tls.get('certificate_key_type')} {tls.get('certificate_key_size')} bits"),
                         ("Signature algorithm", tls.get("signature_algorithm")), ("Issuer", tls.get("issuer")),
                         ("Expiry", tls.get("expiry")),
                         ("Key exchange", f"{pqc.get('group')} (requested, not negotiated)" if pqc.get("hello_retry_request") else pqc.get("group")),
                         ("Draft Kyber", "requested in HelloRetryRequest; acceptance unconfirmed" if pqc.get("draft_requested") else "not determined"),
                         ("Key exchange score", scores["key_exchange_score"]), ("Certificate score", scores["certificate_score"]),
                         ("Overall grade", scores["overall_grade"]), ("Next step", scores["next_step"])):
        lines.append(f"{label}: {value}")
    lines.append(scores["deadline_note"])
    lines.append("Observations may come from different servers; an unselected group may still be supported.")
    return "\n".join(lines)
