"""
The "aha" demo: break a toy RSA key end to end with Shor's algorithm.

Story:
  Alice makes an RSA key with N = 15 and publishes (N, e).
  Bob encrypts a secret message to Alice with her public key.
  Eve (the attacker) sees only the public key and the ciphertext. She runs Shor's
  algorithm on the Aer simulator to factor N, rebuilds Alice's private key from the
  factors, and decrypts Bob's message.

Run it from the project root:
    python -m demos.break_toy_rsa

Honest limits: this works because N = 15 is tiny. Real RSA keys (N with 2048 bits)
are far beyond today's quantum computers; see docs/scaling.png
(made by demos/scaling_chart.py).
"""

from dataclasses import dataclass

from quantum_audit import shor
from quantum_audit.rsa_toy import PublicKey, decrypt, encrypt, generate_keypair, rebuild_private_key

P, Q = 3, 5  # Alice's secret primes
MESSAGE = 7  # Bob's secret message (must be 0..14 for N = 15)


@dataclass
class AttackResult:
    """What Eve learned, so it can be printed or checked by a test."""

    factors: tuple[int, int]  # the factors Shor's found, smallest first
    period: int  # the period r of a^x mod N
    phase: float  # the measured phase that gave r
    d: int  # the private exponent Eve rebuilt
    recovered: int  # the message Eve decrypted


def attack(public_key: PublicKey, ciphertext: int, seed: int | None = None, log=print) -> AttackResult:
    """Eve's side. She gets ONLY the public key and the ciphertext: no p, q, or d.

    `log` is the function used to print steps (pass a no-op to run silently in tests).
    """
    # Our Shor's circuit is hand-built for N = 15 (see quantum_audit/shor.py).
    if public_key.n != shor.N:
        raise ValueError(f"shor.py can only factor N = {shor.N}, not {public_key.n}")

    log(f"\nStep 3. Eve factors N = {public_key.n} with Shor's algorithm (Aer simulator)")
    log(f"        a = {shor.A}, {shor.N_COUNT} counting + {shor.N_WORK} work qubits, {shor.SHOTS} shots")
    result = shor.run_shor(a=shor.A, shots=shor.SHOTS, seed=seed)
    if result.factors is None:
        raise RuntimeError("Shor's found no factors this time; run it again")
    p, q = sorted(result.factors)
    log(f"        Measured phase {result.phase} -> period r = {result.period}")
    log(f"        gcd({shor.A}^{result.period // 2} - 1, {public_key.n}) and "
        f"gcd({shor.A}^{result.period // 2} + 1, {public_key.n}) -> factors {p} and {q}")

    log("\nStep 4. Eve rebuilds the private key from the factors")
    stolen_key = rebuild_private_key(public_key.n, public_key.e, p, q)
    log(f"        phi = ({p} - 1) x ({q} - 1) = {(p - 1) * (q - 1)}")
    log(f"        d = inverse of e = {public_key.e} mod phi  ->  d = {stolen_key.d}")

    log("\nStep 5. Eve decrypts Bob's message with the stolen key")
    recovered = decrypt(ciphertext, stolen_key)
    log(f"        m = c^d mod N = {ciphertext}^{stolen_key.d} mod {public_key.n} = {recovered}")

    return AttackResult(
        factors=(p, q), period=result.period, phase=result.phase, d=stolen_key.d, recovered=recovered
    )


def run_demo(message: int = MESSAGE, seed: int | None = 42, log=print) -> AttackResult:
    """Run the whole story: Alice's key, Bob's encryption, then Eve's attack."""
    log("=== Breaking a toy RSA key with Shor's algorithm ===")

    # Alice's side: she knows p and q, so she can compute everything.
    log(f"\nStep 1. Alice generates an RSA key from secret primes p = {P}, q = {Q}")
    public_key, private_key = generate_keypair(P, Q)
    log(f"        Public key  (anyone can see): N = {public_key.n}, e = {public_key.e}")
    log(f"        Private key (Alice only):     d = {private_key.d}")

    # Bob's side: he only needs the public key.
    log(f"\nStep 2. Bob encrypts the message m = {message} with Alice's public key")
    ciphertext = encrypt(message, public_key)
    log(f"        c = m^e mod N = {message}^{public_key.e} mod {public_key.n} = {ciphertext}")
    log(f"        Eve intercepts c = {ciphertext}. She also has the public key, but not p, q, or d.")

    # Eve's side: everything she uses is passed in explicitly.
    result = attack(public_key, ciphertext, seed=seed, log=log)

    log("\nStep 6. Check")
    log(f"        Original message: {message}   Eve's decrypted message: {result.recovered}")
    if result.recovered == message:
        log("        Match: the toy key is broken.")
    else:
        log("        No match: something went wrong.")
    return result


if __name__ == "__main__":
    run_demo()
