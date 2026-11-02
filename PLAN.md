# quantum-audit — Project Plan

> A quantum-readiness scanner: breaks toy RSA with Shor's algorithm and grades websites on post-quantum security.

## 1. The big idea

Most of the internet is protected by RSA and elliptic-curve cryptography. A large enough quantum computer running
**Shor's algorithm** could break both. That machine doesn't exist yet, but attackers can record encrypted traffic now
and decrypt it later ("harvest now, decrypt later"). The fix is **post-quantum cryptography (PQC)**, which is being
rolled out today.

This project has two halves that tell one story:

| Half | Question it answers | How |
|---|---|---|
| **Attack demo (quantum)** | *Why* is today's encryption at risk? | Run Shor's algorithm in Qiskit to factor a tiny RSA key and decrypt a message |
| **Scanner (classical)** | *Who* is still at risk today? | Passively check real websites' TLS settings and grade their quantum readiness |

Then a **research** section uses the scanner on ~100 popular sites and reports the findings.

---

## 2. Folder structure (target)

```
quantum-audit/
├── PLAN.md                  ← this file
├── CLAUDE.md                ← instructions for Claude Code (tutor mode + ethics rules)
├── README.md                ← public-facing write-up
├── requirements.txt         ← Python libraries
├── experiments/             ← learning circuits (not part of the tool)
│   └── 01_bell_state.py
├── quantum_audit/           ← the actual package
│   ├── __init__.py
│   ├── __main__.py          ← CLI: `python -m quantum_audit scan example.com`
│   ├── rsa_toy.py           ← tiny RSA: keygen, encrypt, decrypt, rebuild key from factors
│   ├── shor.py              ← Shor's algorithm (QFT + modular exponentiation + post-processing)
│   ├── hardware.py          ← optional: run circuits on real IBM quantum hardware
│   ├── scanner.py           ← passive TLS scan of one host
│   ├── pqc.py               ← detect post-quantum key exchange support
│   ├── grading.py           ← turn scan results into an A–F quantum-risk grade
│   └── report.py            ← pretty terminal / JSON / Markdown output
├── demos/
│   └── break_toy_rsa.py     ← end-to-end: encrypt → Shor's → recover key → decrypt
├── research/
│   ├── sites.txt            ← list of sites + category (bank, tech, gov, ...)
│   ├── scan_sites.py        ← batch scan with polite delays → results.csv
│   └── analyze.py           ← charts from results.csv
├── docs/                    ← images used in the README (histograms, charts, screenshots)
└── tests/                   ← pytest tests for each module
```

---

## 3. Components — what each one does

### A. `rsa_toy.py` — Tiny RSA
- Builds an RSA key from two small primes (e.g. 3 × 5 = 15).
- Encrypts / decrypts small integer messages.
- Given the factors of N, rebuilds the private key.
- **Why it matters:** shows that RSA's whole security = "nobody can factor N."

### B. `shor.py` — Shor's algorithm (the quantum core)
- **Quantum part:** finds the *period* of `a^x mod N` using
  1. Hadamard gates to put the counting qubits in superposition,
  2. controlled modular multiplication (the "oracle"),
  3. the inverse **Quantum Fourier Transform (QFT)** to read the period out as a phase.
- **Classical part:** continued fractions → period `r` → `gcd(a^(r/2) ± 1, N)` → the factors.
- Target: factor **N = 15** (with a = 7). Expected answer: **3 and 5**.
- Runs on the Aer simulator by default.

### C. `hardware.py` — Real quantum hardware (optional, free)
- Sends the Shor's circuit to IBM Quantum via `qiskit-ibm-runtime` on the free Open Plan.
- Reads the API token from an environment variable (**never committed**).
- Compares noisy hardware results vs. the clean simulator.

### D. `demos/break_toy_rsa.py` — The "aha" demo
- Generate key → encrypt message → factor N with Shor's → rebuild private key → decrypt.
- Also produces `docs/scaling.png`: qubits needed to break RSA-512/1024/2048 vs. what exists today.

### E. `scanner.py` — Passive TLS scanner
- Makes **one normal HTTPS connection** (port 443) — exactly what a browser does.
- Reads: TLS version, cipher suite, certificate key type (RSA / EC) and size, signature algorithm, issuer, expiry.
- Handles timeouts, bad hostnames, and failed handshakes cleanly.

### F. `pqc.py` — Post-quantum detection
- Checks whether the server negotiates a hybrid post-quantum key exchange (e.g. **X25519MLKEM768**).
- ⚠️ Python's built-in `ssl` module may not be able to offer this group. Plan: check the local OpenSSL version first;
  if it's OpenSSL 3.5+ use it (e.g. `openssl s_client -groups X25519MLKEM768`), otherwise document the limitation.

### G. `grading.py` — Quantum-risk grade
Example rubric (tune as we go):

| Grade | Meaning |
|---|---|
| **A** | TLS 1.3 + post-quantum hybrid key exchange |
| **B** | TLS 1.3, classical key exchange (ECDHE), modern certificate |
| **C** | TLS 1.2 with forward secrecy |
| **D** | TLS 1.2 without forward secrecy, or weak certificate key |
| **F** | TLS 1.0/1.1, broken config, or expired certificate |

Each grade comes with a one-line explanation and a recommendation.
Note: the *certificate* (RSA/ECDSA signature) matters less for "harvest now, decrypt later" than the *key exchange* —
recorded traffic is protected by the key exchange. The report should explain this.

### H. `report.py` + CLI
- `python -m quantum_audit scan google.com` → clean colored report card.
- `--json` flag for machine-readable output (used by the research scripts).

### I. `research/` — The study
- Scan ~100 popular sites across categories (banks, tech, government, universities, news, shopping).
- One connection per site, delay between scans.
- Charts: % with PQ key exchange, TLS versions, certificate key types, grade by category.

---

## 4. Milestones (one Claude Code prompt each)

| # | Milestone | Deliverable | How to check it worked |
|---|---|---|---|
| 1 | Setup + first circuit | venv, requirements.txt, CLAUDE.md, Bell state histogram | ~50% `00`, ~50% `11`, zero `01`/`10` |
| 2 | Toy RSA | `rsa_toy.py` + tests | `pytest` passes; encrypt→decrypt returns the message |
| 3 | Shor's on simulator | `shor.py` + phase histogram | Prints factors **3 and 5** |
| 4 | End-to-end break | `demos/break_toy_rsa.py`, `docs/scaling.png` | Decrypted message matches the original |
| 5 | Real hardware | `hardware.py` | Job completes on IBM; noisy but similar peaks |
| 6 | Scanner core | `scanner.py` + CLI | Results match ssllabs.com/ssltest for 3–5 sites |
| 7 | PQC detection + grading | `pqc.py`, `grading.py`, `report.py` | Cloudflare/Google show PQ support; grades make sense |
| 8 | Research scan | `research/` scripts, CSV, charts | ~100 sites scanned, charts generated |
| 9 | README + polish | Final README with images & findings | A stranger can install and run it from the README |

Rough timeline: ~6–8 weeks at a relaxed pace. Commit and push after every milestone.

---

## 5. Tech stack

- **Python 3.10+**
- **Qiskit** + **qiskit-aer** (simulator) + **qiskit-ibm-runtime** (real hardware)
- **matplotlib** (charts), **pytest** (tests)
- Python `ssl` / `socket`, and the `openssl` CLI for PQ detection
- Optional later: `rich` for nicer terminal output

**Cost:** $0. IBM Open Plan gives free hardware time (10 min / 28 days) — use the simulator for development and save
hardware for final runs.

---

## 6. Ground rules

1. **Passive only.** One normal TLS handshake per site. No port scanning, vulnerability probing, brute forcing,
   or heavy traffic. This is the same information every browser sees.
2. **Polite batch scans.** Delays between sites; never hammer one host.
3. **No secrets in the repo.** IBM token lives in an environment variable / `.env` (gitignored).
4. **Honest claims.** Shor's only breaks *toy* keys today. The README says so clearly.
5. **Understand every file.** Before moving to the next milestone, be able to explain what the code does and why.

---

## 7. Stretch goals (after v1)

- Small web dashboard for scan results
- Grover's algorithm demo (why AES-256 is still safe)
- Factor N = 21 with Shor's
- Track how PQ adoption changes over time (re-run the research scan monthly)
- A post-quantum encryption demo (ML-KEM) to show the fix, not just the threat

---

## 8. Updates from research (Nov 2, 2026) — see `docs/RESEARCH.md`

These override earlier sections where they conflict.

1. **PQ detection (`pqc.py`) → raw TLS 1.3 ClientHello.** Python's `ssl` module can't offer ML-KEM, so we build the
   ClientHello ourselves: offer X25519MLKEM768 (0x11EC) + X25519, read the server's choice from the ServerHello, then
   close the connection. Still passive (less than a normal browser visit). Cross-check with `openssl s_client` /
   testssl.sh / Cloudflare's checker. Unit-test the parser with saved ServerHello bytes.
2. **Flag obsolete draft Kyber (0x6399)** acceptance as a separate finding.
3. **Two separate scores in the report:** *Key exchange* (protects recorded traffic — the urgent one) and
   *Authentication / certificate* (can't be forged retroactively — less urgent, and no PQ certs exist yet). Overall
   grade weights key exchange more.
4. **NIST deadline warnings** in every report: "RSA/ECC deprecated after 2030, disallowed after 2035 (NIST IR 8547)."
5. **Plain-language "one next step"** recommendation per site.
6. **Shor's follows IBM's tutorial approach** (N = 15, a = 2, SWAP-built multipliers) so the hardware run costs ~3 s of
   free QPU time. Stretch: N = 21.
7. **Scaling chart = "the gap is closing" chart:** estimates for breaking RSA-2048 over time (20M → <1M → <100k qubits)
   vs. largest real machines over time.
8. **Output formats:** terminal report, `--json` (JSON Lines), CSV; stretch: CycloneDX **CBOM** export.
9. **Research scan:** use a public top-sites list (e.g. Tranco) + hand-picked categories; written rate-limit policy
   (one handshake per host, ≥1 s delay, low concurrency); compare our % with Cloudflare's ~15% origin figure.
10. **New stretch goals:** SSH key-exchange check (OpenSSH's ML-KEM hybrid), monthly re-scans → adoption-over-time chart.
