# Research notes — what already exists & what we learned (Nov 2, 2026)

## 1. Existing open-source PQC scanners on GitHub

| Project | Language | What it does | What we can borrow |
|---|---|---|---|
| [Quantum-readiness-website-scanner](https://github.com/lazarpetrovic123456/Quantum-readiness-website-scanner) | Python | Hand-builds a raw TLS 1.3 ClientHello offering X25519MLKEM768 + X25519, reads which one the server picks from the ServerHello, never completes the handshake. Verdicts: QUANTUM-SAFE / AT RISK / AT RISK (old TLS 1.2). CSV export. | **The detection technique.** It avoids the problem that Python's `ssl` module / older OpenSSL can't offer ML-KEM. Very small project (1 star, draft README, no findings yet) — so a polished version with real findings is still an open niche. |
| [pqscan](https://github.com/shsingh/pqscan) | Go | TLS + QUIC (HTTP/3) scanner. Fast / deep / PQ-only modes. Flags **obsolete draft Kyber codepoints** as harvest-now-decrypt-later exposure. JSONL/CSV output, pipes into other security tools. Documented rate limits ("etiquette defaults"). | Draft-codepoint detection, JSONL output, written etiquette/rate-limit policy, test-first approach. |
| [pqcprobe](https://github.com/opratr/pqcprobe) | — | Probes TLS config + ML-KEM key-exchange readiness. | Comparison point. |
| [secscan-pqc](https://github.com/Nael-Nathanael/secscan-pqc) | — | Outside-in PQC readiness: ML-KEM, certificates, TLS versions **and SSH**, PDF reports. | SSH scanning + nice reports as stretch ideas. |
| [quantum-ready-labs](https://github.com/manteiga-foundation/quantum-ready-labs) | — | PQ TLS readiness with a **plain-language report and "the one next step."** | Plain-English recommendations in our report. |
| [quantum-resistant-monitor](https://github.com/sparkx313/quantum-resistant-monitor) | — | Tracks PQC adoption across the web over time. | Re-scan monthly → adoption-over-time chart. |
| testssl.sh / sslyze | Bash / Python | Mature general TLS scanners; testssl.sh has added ML-KEM/KEM awareness. | Use to **cross-check** our results. |
| [IBM CBOM](https://www.github.com/IBM/CBOM) / [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/) | spec | Standard "Cryptography Bill of Materials" format for listing crypto assets. | Optional `--cbom` export = makes our output speak the industry's language. |

**Takeaway:** PQC scanners exist, mostly as bare CLI tools. Nobody we found combines **(1) a working Shor's demo, (2) a scanner, (3) an actual research study with findings, and (4) beginner-friendly explanations.** That combination is our differentiator.

## 2. Shor's algorithm references

- **IBM's official tutorial** ([link](https://quantum.cloud.ibm.com/docs/en/tutorials/shors-algorithm)) factors **N = 15 with a = 2**, building the modular-multiplication gates from SWAP gates (much shallower than generic matrices), 8 counting + 4 work qubits, Qiskit 2.x + qiskit-ibm-runtime. Hardware run estimated at **~3 seconds of QPU time** → fits easily in the free 10 min.
- Simulator gives 4 equally likely phases (0, 0.25, 0.5, 0.75); phase 0.25 → period r = 4 → gcd(2² − 1, 15) = **3**.
- Their closing challenge: build it for **N = 21** → our stretch goal.
- Other reference: [aklein4/Shors-Algorithm](https://www.github.com/aklein4/Shors-Algorithm).

## 3. How close is the real threat? (for the scaling chart)

| Year | Estimate to break RSA-2048 | Source |
|---|---|---|
| 2019 | ~20 million noisy qubits, ~8 hours | Gidney & Ekerå |
| May 2025 | < 1 million noisy qubits, < 1 week | [Gidney, arXiv:2505.15917](https://arxiv.org/abs/2505.15917) |
| Feb 2026 | < 100,000 physical qubits (simulation only, qLDPC codes) | Iceberg Quantum, via [The Quantum Insider](https://thequantuminsider.com/?p=2386320) |
| Mar 2026 | 256-bit **elliptic-curve** crypto: < 500,000 qubits, minutes | Google Quantum AI + Boneh + Drake |

Today's largest machines: hundreds to a few thousand physical qubits; ~50–100 logical qubits demonstrated.
**Story for the README:** estimates have fallen ~200× in 7 years while hardware keeps growing — the gap is closing from both sides.
Also: ECC (used in most TLS key exchanges today) may fall *before* RSA.

## 4. Deadlines (for grading & report text)

- **NIST IR 8547 (final, Oct 27, 2026):** quantum-vulnerable algorithms (RSA, ECDSA, EdDSA, ECDH, finite-field DH) are **deprecated after 2030** and **disallowed after 2035**. ([CSA summary](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ir8547-pqc-transition-20261030-csa-st/))
- NIST recommends **ML-KEM-768** as the default; hybrids (ML-KEM + ECDH) are acceptable.
- Federal high-value systems (EO 14412): PQ key establishment by **end of 2030**, PQ signatures by **end of 2031**.

## 5. Real-world adoption numbers (to compare our research against)

From [Cloudflare (Sep 29, 2026)](https://blog.cloudflare.com/post-quantum-visibility/):
- ~**70%** of browser traffic to Cloudflare uses hybrid ML-KEM.
- Only ~**15%** of origin servers Cloudflare connects to support it.
- **X25519MLKEM768** is the only recommended PQ group for TLS 1.3; **TLS 1.2 has no PQ option at all.**
- PQ *encryption* is far ahead of PQ *authentication* (certificates) — nobody has PQ certificates in the web PKI yet.

Hypothesis for our study: sites behind big CDNs (Cloudflare, Google, Akamai) score A; banks, government and universities with their own servers lag.

## 6. Technical gotchas

- Python's `ssl.SSLContext.set_ecdh_curve()` **cannot** set PQ groups (OpenSSL NID validation). → Use the raw ClientHello approach (or `openssl s_client -groups X25519MLKEM768` with OpenSSL 3.5+ as a cross-check).
- X25519MLKEM768 codepoint = **0x11EC**. Obsolete draft `X25519Kyber768Draft00` = **0x6399**.
- Big sites have many servers/IPs — one scan = one server. Note it as a limitation.
- School/corporate networks may intercept TLS → scan from home Wi-Fi.
